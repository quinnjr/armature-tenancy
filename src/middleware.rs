//! Tenant Middleware
//!
//! Resolves the request's tenant and binds it to the authenticated principal.
//!
//! # Principal binding
//!
//! Resolving a tenant (from a header, subdomain, path or token claim) only
//! answers *which* tenant a request is about. [`TenantMiddleware`] also checks
//! that the caller is allowed into that tenant: it requires the verified
//! [`UserContext`] that `armature_auth::JwtAuthMiddleware` attaches (so that
//! middleware must be registered **before** this one) and accepts the request
//! only if the resolved tenant's [`Tenant::id`](crate::Tenant) is one of the
//! principal's tenants.
//!
//! The principal's tenants are read from the verified claim set kept in
//! [`UserContext::metadata`], as configured by [`TenantMembership`]:
//!
//! - the `tenants` claim (configurable): a JSON array of tenant ids, or a
//!   single tenant-id string;
//! - else the `tenant_id` claim (configurable): a single tenant-id string.
//!
//! Outcomes: no verified `UserContext` → `401`; tenant resolved but not one of
//! the principal's tenants → `403`.

use crate::resolver::TenantResolver;
use crate::tenant::TenantContext;
use armature_auth::UserContext;
use armature_core::{Error, HttpRequest, HttpResponse, Middleware};
use async_trait::async_trait;
use std::sync::Arc;

/// Where the authenticated principal's tenant memberships are read from.
///
/// Claims are looked up in [`UserContext::metadata`], the verified claim set
/// `armature_auth::JwtAuthMiddleware` stores there. The default reads the
/// `tenants` claim (array of tenant ids, or a single string) and falls back to
/// the `tenant_id` claim (single string).
///
/// ```
/// use armature_auth::UserContext;
/// use armature_tenancy::TenantMembership;
/// use serde_json::json;
///
/// let user = UserContext::new("u1".to_string())
///     .with_metadata(json!({ "tenants": ["t-1", "t-2"] }));
/// let membership = TenantMembership::default();
/// assert_eq!(membership.tenants_of(&user), vec!["t-1", "t-2"]);
///
/// let user = UserContext::new("u2".to_string()).with_metadata(json!({ "org": "t-9" }));
/// let membership = TenantMembership::new("org");
/// assert!(membership.is_member(&user, "t-9"));
/// ```
#[derive(Debug, Clone)]
pub struct TenantMembership {
    tenants_claim: String,
    single_tenant_claim: Option<String>,
}

impl TenantMembership {
    /// Read memberships from `tenants_claim` only (array or single string).
    pub fn new(tenants_claim: impl Into<String>) -> Self {
        Self {
            tenants_claim: tenants_claim.into(),
            single_tenant_claim: None,
        }
    }

    /// Also accept a single-tenant string claim when `tenants_claim` is absent.
    pub fn with_single_tenant_claim(mut self, claim: impl Into<String>) -> Self {
        self.single_tenant_claim = Some(claim.into());
        self
    }

    /// The tenant ids the verified principal belongs to.
    pub fn tenants_of(&self, user: &UserContext) -> Vec<String> {
        let strings = |value: &serde_json::Value| -> Vec<String> {
            match value {
                serde_json::Value::String(s) if !s.is_empty() => vec![s.clone()],
                serde_json::Value::Array(items) => items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            }
        };
        if let Some(value) = user.metadata.get(&self.tenants_claim) {
            return strings(value);
        }
        match &self.single_tenant_claim {
            Some(claim) => match user.metadata.get(claim) {
                Some(serde_json::Value::String(s)) if !s.is_empty() => vec![s.clone()],
                _ => Vec::new(),
            },
            None => Vec::new(),
        }
    }

    /// Whether the verified principal belongs to `tenant_id`.
    pub fn is_member(&self, user: &UserContext, tenant_id: &str) -> bool {
        self.tenants_of(user).iter().any(|t| t == tenant_id)
    }
}

impl Default for TenantMembership {
    fn default() -> Self {
        Self::new("tenants").with_single_tenant_claim("tenant_id")
    }
}

/// Tenant middleware
///
/// Resolves the tenant, binds it to the verified principal (see the
/// [module docs](self)), and stores it in [`TenantContext`].
pub struct TenantMiddleware {
    resolver: Arc<dyn TenantResolver>,
    optional: bool,
    /// `None` only for [`TenantMiddleware::public_unverified`].
    membership: Option<TenantMembership>,
}

impl TenantMiddleware {
    /// Create new tenant middleware that binds the tenant to the principal
    /// using [`TenantMembership::default`].
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use armature_auth::JwtAuthMiddleware;
    /// use armature_tenancy::{TenantMiddleware, SubdomainTenantResolver};
    /// use std::sync::Arc;
    ///
    /// // JwtAuthMiddleware first: it attaches the verified UserContext.
    /// app.middleware(Arc::new(JwtAuthMiddleware::new(jwt_manager)));
    /// let resolver = Arc::new(SubdomainTenantResolver::new(store, "example.com"));
    /// app.middleware(Arc::new(TenantMiddleware::new(resolver)));
    /// ```
    pub fn new(resolver: Arc<dyn TenantResolver>) -> Self {
        Self {
            resolver,
            optional: false,
            membership: Some(TenantMembership::default()),
        }
    }

    /// Tenant middleware for public, unauthenticated pages (e.g. a tenant's
    /// marketing site resolved by subdomain).
    ///
    /// **This is not an authorization check.** The tenant is resolved but not
    /// bound to any principal; the stored [`TenantContext`] reports
    /// [`is_principal_bound`](TenantContext::is_principal_bound) `== false`
    /// and must only be used to pick public, per-tenant content — never to
    /// read or write tenant data.
    pub fn public_unverified(resolver: Arc<dyn TenantResolver>) -> Self {
        Self {
            resolver,
            optional: false,
            membership: None,
        }
    }

    /// Use a custom membership claim layout.
    pub fn with_membership(mut self, membership: TenantMembership) -> Self {
        if self.membership.is_some() {
            self.membership = Some(membership);
        }
        self
    }

    /// Make tenant resolution optional
    ///
    /// If true, requests whose tenant cannot be *resolved* proceed with no
    /// tenant. A request whose tenant resolves but is not one of the
    /// principal's tenants is still rejected with `403`.
    /// If false, requests without valid tenant will return 401.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let middleware = TenantMiddleware::new(resolver)
    ///     .with_optional(true);
    /// ```
    pub fn with_optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }
}

/// Internal header-name prefix that once carried the resolved tenant.
///
/// Tenant identity is now stored in [`HttpRequest::extensions`], never in
/// headers. Any incoming header whose name starts with this prefix is
/// attacker-controlled noise and is stripped before resolution so a client
/// can never seed the request-local tenant identity.
const INTERNAL_TENANT_HEADER_PREFIX: &str = "__tenant";

/// Remove every client-supplied `__tenant*` header from the request.
///
/// Header lookup in [`HttpRequest`] is case-insensitive, so we match the
/// prefix case-insensitively to avoid a `__Tenant_Id`-style bypass.
fn strip_incoming_tenant_headers(request: &mut HttpRequest) {
    let to_remove: Vec<String> = request
        .headers
        .names()
        .filter(|name| {
            name.as_bytes()
                .get(..INTERNAL_TENANT_HEADER_PREFIX.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(INTERNAL_TENANT_HEADER_PREFIX.as_bytes()))
        })
        // Owned, because the loop below mutates the same map it is iterating
        // the names of.
        .map(str::to_owned)
        .collect();

    for name in to_remove {
        request.headers.remove_all(&name);
    }
}

#[async_trait]
impl Middleware for TenantMiddleware {
    async fn handle(
        &self,
        mut request: HttpRequest,
        next: armature_core::middleware::Next,
    ) -> Result<HttpResponse, Error> {
        // Defense in depth: strip any client-supplied `__tenant*` headers
        // BEFORE resolution. Tenant identity lives only in request-local
        // extensions, so a spoofed header can never be mistaken for a
        // resolved tenant (closes the isolation bypass).
        strip_incoming_tenant_headers(&mut request);
        request.extensions.remove::<TenantContext>();

        // Resolve tenant
        match self.resolver.resolve(&request).await {
            Ok(tenant) => {
                let context = match &self.membership {
                    Some(membership) => {
                        // Bind the tenant to the verified principal: a
                        // resolver only says which tenant the request names.
                        let user = request.extensions.get::<UserContext>().ok_or_else(|| {
                            Error::Unauthorized(
                                "Tenant access requires an authenticated principal".to_string(),
                            )
                        })?;
                        if !membership.is_member(user, &tenant.id) {
                            return Err(Error::Forbidden(
                                "Principal is not a member of the requested tenant".to_string(),
                            ));
                        }
                        TenantContext::bound_to_principal(tenant)
                    }
                    None => TenantContext::with_tenant(tenant),
                };

                // Store the resolved tenant identity in request-local,
                // type-safe storage that clients cannot influence.
                request.extensions.insert(context);

                // Continue with request
                next(request).await
            }
            Err(e) => {
                if self.optional {
                    // Optional mode: proceed with NO tenant identity present.
                    // Headers were stripped above, and no TenantContext was
                    // inserted here, but defense-in-depth: remove any
                    // TenantContext that may have been preset on the request
                    // (e.g. by a server/framework default) before continuing,
                    // so a resolution failure can never let a stale/preset
                    // tenant context leak through.
                    request.extensions.remove::<TenantContext>();
                    next(request).await
                } else {
                    // Return error
                    Err(Error::Unauthorized(format!(
                        "Tenant resolution failed: {}",
                        e
                    )))
                }
            }
        }
    }
}

/// Helper to extract the resolved tenant id from a request.
///
/// Reads the [`TenantContext`] that [`TenantMiddleware`] stores in
/// [`HttpRequest::extensions`] on successful resolution. Returns `None` when
/// no tenant was resolved (anonymous). Client-supplied headers are never
/// consulted, so they cannot spoof the tenant.
pub fn get_tenant_id(request: &HttpRequest) -> Option<String> {
    request
        .extensions
        .get::<TenantContext>()
        .and_then(|ctx| ctx.tenant_id().map(str::to_string))
}

/// Helper to extract the resolved tenant name from a request.
///
/// Reads from [`HttpRequest::extensions`] (see [`get_tenant_id`]); never from
/// headers.
pub fn get_tenant_name(request: &HttpRequest) -> Option<String> {
    request
        .extensions
        .get::<TenantContext>()
        .and_then(|ctx| ctx.tenant().map(|tenant| tenant.name.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TenantError;
    use crate::tenant::Tenant;

    struct MockResolver {
        tenant: Option<Tenant>,
    }

    #[async_trait]
    impl TenantResolver for MockResolver {
        async fn resolve(&self, _request: &HttpRequest) -> Result<Tenant, TenantError> {
            self.tenant
                .clone()
                .ok_or_else(|| TenantError::NotFound("No tenant".to_string()))
        }
    }

    fn create_request() -> HttpRequest {
        HttpRequest::new("GET", "/api/users".to_string())
    }

    /// A request carrying a verified principal that belongs to `tenants`.
    fn member_request(tenants: serde_json::Value) -> HttpRequest {
        let mut request = create_request();
        request.extensions.insert(
            UserContext::new("user-1".to_string())
                .with_metadata(serde_json::json!({ "sub": "user-1", "tenants": tenants })),
        );
        request
    }

    fn ok_next() -> armature_core::middleware::Next {
        Box::new(|_req| Box::pin(async move { Ok(HttpResponse::ok()) }))
    }

    struct Store;

    #[async_trait]
    impl crate::TenantStore for Store {
        async fn find_by_id(&self, id: &str) -> Result<Option<Tenant>, TenantError> {
            Ok(match id {
                "tenant-a" => Some(Tenant::new("tenant-a", "alpha")),
                "tenant-b" => Some(Tenant::new("tenant-b", "beta")),
                _ => None,
            })
        }
        async fn find_by_name(&self, _name: &str) -> Result<Option<Tenant>, TenantError> {
            Ok(None)
        }
        async fn find_by_domain(&self, _domain: &str) -> Result<Option<Tenant>, TenantError> {
            Ok(None)
        }
    }

    fn header_middleware() -> TenantMiddleware {
        TenantMiddleware::new(Arc::new(crate::HeaderTenantResolver::trusted_internal(
            Arc::new(Store),
            "X-Tenant-ID",
        )))
    }

    /// H14 regression: a principal verified for tenant A cannot reach tenant B
    /// by naming it in `X-Tenant-ID`.
    #[tokio::test]
    async fn cross_tenant_header_is_forbidden() {
        let mut request = member_request(serde_json::json!(["tenant-a"]));
        request
            .headers
            .insert("x-tenant-id", "tenant-b".to_string());

        let result = header_middleware().handle(request, ok_next()).await;
        assert!(matches!(result, Err(Error::Forbidden(_))), "{result:?}");
    }

    #[tokio::test]
    async fn own_tenant_header_is_allowed_and_bound() {
        let mut request = member_request(serde_json::json!(["tenant-a", "tenant-b"]));
        request
            .headers
            .insert("x-tenant-id", "tenant-b".to_string());

        let result = header_middleware()
            .handle(
                request,
                Box::new(|req| {
                    Box::pin(async move {
                        let ctx = req.extensions.get::<TenantContext>().unwrap();
                        assert_eq!(ctx.tenant_id(), Some("tenant-b"));
                        assert!(ctx.is_principal_bound());
                        Ok(HttpResponse::ok())
                    })
                }),
            )
            .await;
        assert!(result.is_ok());
    }

    /// No verified `UserContext` (e.g. only a forged/unsigned bearer token in
    /// the header, which nothing verified) → 401, no tenant attached.
    #[tokio::test]
    async fn unverified_request_is_unauthorized() {
        let mut request = create_request();
        request
            .headers
            .insert("x-tenant-id", "tenant-a".to_string());
        request.headers.insert(
            "authorization",
            "Bearer eyJhbGciOiJub25lIn0.eyJ0ZW5hbnRzIjpbInRlbmFudC1hIl19.".to_string(),
        );

        let result = header_middleware().handle(request, ok_next()).await;
        assert!(matches!(result, Err(Error::Unauthorized(_))), "{result:?}");

        // Same through the JWT resolver: it never decodes the raw header.
        let mw = TenantMiddleware::new(Arc::new(crate::JwtTenantResolver::new(
            Arc::new(Store),
            "tenant_id",
        )));
        let mut request = create_request();
        request.headers.insert(
            "authorization",
            "Bearer eyJhbGciOiJub25lIn0.eyJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtYSJ9.".to_string(),
        );
        let result = mw.handle(request, ok_next()).await;
        assert!(matches!(result, Err(Error::Unauthorized(_))), "{result:?}");
    }

    /// Optional mode only tolerates *unresolved* tenants; a resolved tenant
    /// the principal does not belong to is still forbidden.
    #[tokio::test]
    async fn optional_mode_still_enforces_membership() {
        let mut request = member_request(serde_json::json!("tenant-a"));
        request
            .headers
            .insert("x-tenant-id", "tenant-b".to_string());

        let result = header_middleware()
            .with_optional(true)
            .handle(request, ok_next())
            .await;
        assert!(matches!(result, Err(Error::Forbidden(_))), "{result:?}");
    }

    #[tokio::test]
    async fn single_tenant_id_claim_fallback() {
        let mut request = create_request();
        request.extensions.insert(
            UserContext::new("u".to_string())
                .with_metadata(serde_json::json!({ "tenant_id": "tenant-a" })),
        );
        request
            .headers
            .insert("x-tenant-id", "tenant-a".to_string());
        assert!(header_middleware().handle(request, ok_next()).await.is_ok());
    }

    #[tokio::test]
    async fn public_unverified_resolves_without_binding() {
        let mw = TenantMiddleware::public_unverified(Arc::new(
            crate::HeaderTenantResolver::trusted_internal(Arc::new(Store), "X-Tenant-ID"),
        ));
        let mut request = create_request();
        request
            .headers
            .insert("x-tenant-id", "tenant-a".to_string());

        let result = mw
            .handle(
                request,
                Box::new(|req| {
                    Box::pin(async move {
                        let ctx = req.extensions.get::<TenantContext>().unwrap();
                        assert_eq!(ctx.tenant_id(), Some("tenant-a"));
                        assert!(!ctx.is_principal_bound());
                        Ok(HttpResponse::ok())
                    })
                }),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn preset_tenant_context_is_discarded() {
        // A context planted before the middleware runs must never survive.
        let mut request = create_request();
        request
            .extensions
            .insert(TenantContext::with_tenant(Tenant::new("victim", "victim")));
        let mw = TenantMiddleware::new(Arc::new(MockResolver { tenant: None })).with_optional(true);
        let result = mw
            .handle(
                request,
                Box::new(|req| {
                    Box::pin(async move {
                        assert_eq!(get_tenant_id(&req), None);
                        Ok(HttpResponse::ok())
                    })
                }),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_middleware_with_tenant() {
        let tenant = Tenant::new("tenant-1", "acme");
        let resolver = Arc::new(MockResolver {
            tenant: Some(tenant.clone()),
        });
        let middleware = TenantMiddleware::new(resolver);

        let request = member_request(serde_json::json!(["tenant-1"]));

        let result = middleware
            .handle(
                request,
                Box::new(|req| {
                    Box::pin(async move {
                        // Check tenant was stored
                        assert_eq!(get_tenant_id(&req), Some("tenant-1".to_string()));
                        assert_eq!(get_tenant_name(&req), Some("acme".to_string()));
                        Ok(HttpResponse::ok())
                    })
                }),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_middleware_without_tenant_required() {
        let resolver = Arc::new(MockResolver { tenant: None });
        let middleware = TenantMiddleware::new(resolver).with_optional(false);

        let request = create_request();

        let result = middleware
            .handle(
                request,
                Box::new(|_req| Box::pin(async move { Ok(HttpResponse::ok()) })),
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn enforcing_mode_rejects_unresolved() {
        let resolver = Arc::new(MockResolver { tenant: None });
        let middleware = TenantMiddleware::new(resolver).with_optional(false);

        // Even a spoofed header must not rescue an unresolved request.
        let mut request = create_request();
        request.headers.insert("__tenant_id", "victim".to_string());

        let result = middleware
            .handle(
                request,
                Box::new(|_req| Box::pin(async move { Ok(HttpResponse::ok()) })),
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized(_))));
    }

    #[tokio::test]
    async fn successful_resolution_exposes_tenant_via_extensions() {
        let tenant = Tenant::new("tenant-1", "acme");
        let resolver = Arc::new(MockResolver {
            tenant: Some(tenant),
        });
        let middleware = TenantMiddleware::new(resolver);

        // Client tries to spoof a different tenant; the resolved one must win.
        let mut request = member_request(serde_json::json!(["tenant-1"]));
        request.headers.insert("__tenant_id", "victim".to_string());
        request
            .headers
            .insert("__tenant_name", "victim-corp".to_string());

        let result = middleware
            .handle(
                request,
                Box::new(|req| {
                    Box::pin(async move {
                        assert_eq!(get_tenant_id(&req), Some("tenant-1".to_string()));
                        assert_eq!(get_tenant_name(&req), Some("acme".to_string()));
                        Ok(HttpResponse::ok())
                    })
                }),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn optional_mode_ignores_client_supplied_tenant_header() {
        // A resolver that FAILS, in optional mode, with a client trying to
        // seed the internal tenant header. The spoof must NOT survive.
        let resolver = Arc::new(MockResolver { tenant: None });
        let middleware = TenantMiddleware::new(resolver).with_optional(true);

        let mut request = create_request();
        request.headers.insert("__tenant_id", "victim".to_string());
        request
            .headers
            .insert("__tenant_name", "victim-corp".to_string());

        let result = middleware
            .handle(
                request,
                Box::new(|req| {
                    Box::pin(async move {
                        assert_eq!(get_tenant_id(&req), None, "spoofed tenant id survived");
                        assert_eq!(get_tenant_name(&req), None, "spoofed tenant name survived");
                        Ok(HttpResponse::ok())
                    })
                }),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_middleware_without_tenant_optional() {
        let resolver = Arc::new(MockResolver { tenant: None });
        let middleware = TenantMiddleware::new(resolver).with_optional(true);

        let request = create_request();

        let result = middleware
            .handle(
                request,
                Box::new(|req| {
                    Box::pin(async move {
                        // No tenant should be stored
                        assert_eq!(get_tenant_id(&req), None);
                        Ok(HttpResponse::ok())
                    })
                }),
            )
            .await;

        assert!(result.is_ok());
    }
}
