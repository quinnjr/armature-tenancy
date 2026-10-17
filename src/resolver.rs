//! Tenant Resolution
//!
//! Strategies for resolving tenant from HTTP requests.

use crate::tenant::Tenant;
use armature_auth::UserContext;
use armature_core::HttpRequest;
use async_trait::async_trait;
use regex::Regex;
use std::sync::Arc;

/// Tenant resolution errors
#[derive(Debug, thiserror::Error)]
pub enum TenantError {
    #[error("Tenant not found: {0}")]
    NotFound(String),

    #[error("Invalid tenant identifier: {0}")]
    Invalid(String),

    #[error("Tenant resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("Tenant is inactive")]
    Inactive,

    #[error("Storage error: {0}")]
    Storage(String),
}

/// Tenant resolver trait
///
/// Implement this trait to provide tenant resolution logic.
/// Users must inject their own tenant store via DI.
#[async_trait]
pub trait TenantResolver: Send + Sync {
    /// Resolve tenant from request
    async fn resolve(&self, request: &HttpRequest) -> Result<Tenant, TenantError>;
}

/// Tenant store trait (implement with your database)
///
/// Users provide their own implementation using their database of choice.
#[async_trait]
pub trait TenantStore: Send + Sync {
    /// Find tenant by ID
    async fn find_by_id(&self, id: &str) -> Result<Option<Tenant>, TenantError>;

    /// Find tenant by name/slug
    async fn find_by_name(&self, name: &str) -> Result<Option<Tenant>, TenantError>;

    /// Find tenant by domain
    async fn find_by_domain(&self, domain: &str) -> Result<Option<Tenant>, TenantError>;
}

/// Header-based tenant resolver for **trusted, internal** traffic only.
///
/// Resolves tenant from a request header (e.g., `X-Tenant-ID`). A client can
/// put any value in a header, so this resolver only selects *which* tenant the
/// request is about; it never proves the caller may access it.
/// [`crate::TenantMiddleware`] still binds the resolved tenant to the verified
/// principal's tenant memberships, so a caller authenticated for tenant `A`
/// sending `X-Tenant-ID: B` is rejected with `403`.
///
/// Use it only behind a gateway/service mesh that sets the header itself and
/// strips client-supplied copies. There is deliberately no `new`: the
/// constructor is named [`trusted_internal`](Self::trusted_internal) so that
/// choosing this resolver is an explicit decision.
pub struct HeaderTenantResolver {
    store: Arc<dyn TenantStore>,
    header_name: String,
}

impl HeaderTenantResolver {
    /// Create a header-based resolver for trusted, internal traffic.
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_tenancy::HeaderTenantResolver;
    /// use std::sync::Arc;
    ///
    /// # struct MyTenantStore;
    /// # #[async_trait::async_trait]
    /// # impl armature_tenancy::TenantStore for MyTenantStore {
    /// #     async fn find_by_id(&self, id: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// #     async fn find_by_name(&self, name: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// #     async fn find_by_domain(&self, domain: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// # }
    /// let store: Arc<dyn armature_tenancy::TenantStore> = Arc::new(MyTenantStore);
    /// let resolver = HeaderTenantResolver::trusted_internal(store, "X-Tenant-ID");
    /// ```
    pub fn trusted_internal(store: Arc<dyn TenantStore>, header_name: impl Into<String>) -> Self {
        Self {
            store,
            header_name: header_name.into(),
        }
    }
}

#[async_trait]
impl TenantResolver for HeaderTenantResolver {
    async fn resolve(&self, request: &HttpRequest) -> Result<Tenant, TenantError> {
        // `HeaderMap::get` is already case-insensitive, so lowercasing the
        // configured name here would allocate a `String` per request for nothing.
        let tenant_id = request.headers.get(&self.header_name).ok_or_else(|| {
            TenantError::NotFound(format!("Missing header: {}", self.header_name))
        })?;

        let tenant = self
            .store
            .find_by_id(tenant_id)
            .await?
            .ok_or_else(|| TenantError::NotFound(tenant_id.to_owned()))?;

        if !tenant.active {
            return Err(TenantError::Inactive);
        }

        Ok(tenant)
    }
}

/// Subdomain-based tenant resolver
///
/// Resolves tenant from subdomain (e.g., `acme.example.com` -> tenant "acme").
pub struct SubdomainTenantResolver {
    store: Arc<dyn TenantStore>,
    base_domain: String,
}

impl SubdomainTenantResolver {
    /// Create new subdomain-based resolver
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_tenancy::SubdomainTenantResolver;
    /// use std::sync::Arc;
    ///
    /// # struct MyTenantStore;
    /// # #[async_trait::async_trait]
    /// # impl armature_tenancy::TenantStore for MyTenantStore {
    /// #     async fn find_by_id(&self, id: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// #     async fn find_by_name(&self, name: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// #     async fn find_by_domain(&self, domain: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// # }
    /// let store: Arc<dyn armature_tenancy::TenantStore> = Arc::new(MyTenantStore);
    /// let resolver = SubdomainTenantResolver::new(store, "example.com");
    /// ```
    pub fn new(store: Arc<dyn TenantStore>, base_domain: impl Into<String>) -> Self {
        Self {
            store,
            base_domain: base_domain.into(),
        }
    }

    /// Extract subdomain from host header
    fn extract_subdomain(&self, host: &str) -> Option<String> {
        // Remove port if present
        let host = host.split(':').next().unwrap_or(host);

        // Remove base domain
        if let Some(subdomain) = host.strip_suffix(&format!(".{}", self.base_domain))
            && !subdomain.is_empty()
            && !subdomain.contains('.')
        {
            return Some(subdomain.to_string());
        }

        None
    }
}

#[async_trait]
impl TenantResolver for SubdomainTenantResolver {
    async fn resolve(&self, request: &HttpRequest) -> Result<Tenant, TenantError> {
        let host = request
            .headers
            .get("host")
            .ok_or_else(|| TenantError::ResolutionFailed("Missing Host header".to_string()))?;

        let subdomain = self
            .extract_subdomain(host)
            .ok_or_else(|| TenantError::ResolutionFailed(format!("No subdomain in: {}", host)))?;

        let tenant = self
            .store
            .find_by_name(&subdomain)
            .await?
            .ok_or_else(|| TenantError::NotFound(subdomain.clone()))?;

        if !tenant.active {
            return Err(TenantError::Inactive);
        }

        Ok(tenant)
    }
}

/// JWT claim-based tenant resolver
///
/// Resolves the tenant from a claim of the **verified** token: it reads the
/// [`UserContext`] request extension that `armature_auth::JwtAuthMiddleware`
/// inserts after checking the token's signature and expiry (the full verified
/// claim set lives in [`UserContext::metadata`]). The raw `Authorization`
/// header is never decoded, so a forged or unsigned token cannot select a
/// tenant. `JwtAuthMiddleware` must therefore run before
/// [`crate::TenantMiddleware`].
///
/// The claim must be a non-empty string, or an array holding exactly one
/// non-empty string. Anything else fails closed.
pub struct JwtTenantResolver {
    store: Arc<dyn TenantStore>,
    claim_name: String,
}

impl JwtTenantResolver {
    /// Create new JWT-based resolver
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_tenancy::JwtTenantResolver;
    /// use std::sync::Arc;
    ///
    /// # struct MyTenantStore;
    /// # #[async_trait::async_trait]
    /// # impl armature_tenancy::TenantStore for MyTenantStore {
    /// #     async fn find_by_id(&self, id: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// #     async fn find_by_name(&self, name: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// #     async fn find_by_domain(&self, domain: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// # }
    /// let store: Arc<dyn armature_tenancy::TenantStore> = Arc::new(MyTenantStore);
    /// let resolver = JwtTenantResolver::new(store, "tenant_id");
    /// ```
    pub fn new(store: Arc<dyn TenantStore>, claim_name: impl Into<String>) -> Self {
        Self {
            store,
            claim_name: claim_name.into(),
        }
    }

    /// Read the configured claim from the verified claim set.
    fn extract_claim(&self, user: &UserContext) -> Result<String, TenantError> {
        let invalid = || {
            TenantError::Invalid(format!(
                "claim '{}' is not a non-empty string",
                self.claim_name
            ))
        };
        match user.metadata.get(&self.claim_name) {
            Some(serde_json::Value::String(value)) if !value.is_empty() => Ok(value.clone()),
            Some(serde_json::Value::Array(items)) => match items.as_slice() {
                [serde_json::Value::String(value)] if !value.is_empty() => Ok(value.clone()),
                _ => Err(invalid()),
            },
            Some(_) => Err(invalid()),
            None => Err(TenantError::ResolutionFailed(format!(
                "verified token is missing the '{}' claim",
                self.claim_name
            ))),
        }
    }
}

#[async_trait]
impl TenantResolver for JwtTenantResolver {
    async fn resolve(&self, request: &HttpRequest) -> Result<Tenant, TenantError> {
        let user = request.extensions.get::<UserContext>().ok_or_else(|| {
            TenantError::ResolutionFailed(
                "no verified UserContext on the request (is JwtAuthMiddleware registered first?)"
                    .to_string(),
            )
        })?;

        let tenant_id = self.extract_claim(user)?;

        let tenant = self
            .store
            .find_by_id(&tenant_id)
            .await?
            .ok_or_else(|| TenantError::NotFound(tenant_id.clone()))?;

        if !tenant.active {
            return Err(TenantError::Inactive);
        }

        Ok(tenant)
    }
}

/// Path-based tenant resolver
///
/// Resolves tenant from URL path (e.g., `/tenants/acme/users`).
pub struct PathTenantResolver {
    store: Arc<dyn TenantStore>,
    pattern: Regex,
    group_index: usize,
}

impl PathTenantResolver {
    /// Create new path-based resolver
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_tenancy::PathTenantResolver;
    /// use std::sync::Arc;
    ///
    /// # struct MyTenantStore;
    /// # #[async_trait::async_trait]
    /// # impl armature_tenancy::TenantStore for MyTenantStore {
    /// #     async fn find_by_id(&self, id: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// #     async fn find_by_name(&self, name: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// #     async fn find_by_domain(&self, domain: &str) -> Result<Option<armature_tenancy::Tenant>, armature_tenancy::TenantError> { Ok(None) }
    /// # }
    /// let store: Arc<dyn armature_tenancy::TenantStore> = Arc::new(MyTenantStore);
    /// let resolver = PathTenantResolver::new(store, r"^/tenants/([^/]+)", 1).unwrap();
    /// ```
    pub fn new(
        store: Arc<dyn TenantStore>,
        pattern: &str,
        group_index: usize,
    ) -> Result<Self, regex::Error> {
        Ok(Self {
            store,
            pattern: Regex::new(pattern)?,
            group_index,
        })
    }
}

#[async_trait]
impl TenantResolver for PathTenantResolver {
    async fn resolve(&self, request: &HttpRequest) -> Result<Tenant, TenantError> {
        // `path_only`, not `path`: the raw target still carries the query
        // string, which would otherwise be captured as part of the tenant id
        // (`/tenants/acme?page=2` -> `acme?page=2`) and fail to resolve.
        let captures = self
            .pattern
            .captures(request.path_only())
            .ok_or_else(|| TenantError::ResolutionFailed("Path pattern not matched".to_string()))?;

        let tenant_name = captures
            .get(self.group_index)
            .ok_or_else(|| TenantError::ResolutionFailed("Capture group not found".to_string()))?
            .as_str();

        let tenant = self
            .store
            .find_by_name(tenant_name)
            .await?
            .ok_or_else(|| TenantError::NotFound(tenant_name.to_string()))?;

        if !tenant.active {
            return Err(TenantError::Inactive);
        }

        Ok(tenant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockTenantStore {
        tenants: HashMap<String, Tenant>,
    }

    impl MockTenantStore {
        fn new() -> Self {
            let mut tenants = HashMap::new();
            tenants.insert(
                "tenant-1".to_string(),
                Tenant::new("tenant-1", "acme").with_domain("acme.example.com"),
            );
            tenants.insert(
                "tenant-2".to_string(),
                Tenant::new("tenant-2", "globex").with_domain("globex.example.com"),
            );
            Self { tenants }
        }
    }

    #[async_trait]
    impl TenantStore for MockTenantStore {
        async fn find_by_id(&self, id: &str) -> Result<Option<Tenant>, TenantError> {
            Ok(self.tenants.get(id).cloned())
        }

        async fn find_by_name(&self, name: &str) -> Result<Option<Tenant>, TenantError> {
            Ok(self.tenants.values().find(|t| t.name == name).cloned())
        }

        async fn find_by_domain(&self, domain: &str) -> Result<Option<Tenant>, TenantError> {
            Ok(self
                .tenants
                .values()
                .find(|t| t.domain.as_deref() == Some(domain))
                .cloned())
        }
    }

    fn create_request(method: &str, path: &str) -> HttpRequest {
        HttpRequest::new(method.to_string(), path.to_string())
    }

    #[tokio::test]
    async fn test_header_resolver() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = HeaderTenantResolver::trusted_internal(store, "X-Tenant-ID");

        let mut request = create_request("GET", "/api/users");
        request
            .headers
            .insert("x-tenant-id", "tenant-1".to_string());

        let tenant = resolver.resolve(&request).await.unwrap();
        assert_eq!(tenant.id, "tenant-1");
        assert_eq!(tenant.name, "acme");
    }

    #[tokio::test]
    async fn test_subdomain_resolver() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = SubdomainTenantResolver::new(store, "example.com");

        let mut request = create_request("GET", "/api/users");
        request
            .headers
            .insert("host", "acme.example.com".to_string());

        let tenant = resolver.resolve(&request).await.unwrap();
        assert_eq!(tenant.name, "acme");
    }

    /// Build an (unsigned) JWT with the given JSON payload.
    fn make_jwt(payload: &serde_json::Value) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
            URL_SAFE_NO_PAD.encode(b"signature")
        )
    }

    fn verified(claims: serde_json::Value) -> UserContext {
        UserContext::new("user-1".to_string()).with_metadata(claims)
    }

    #[tokio::test]
    async fn test_jwt_resolver_reads_verified_context() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = JwtTenantResolver::new(store, "tenant_id");

        let mut request = create_request("GET", "/api/users");
        request.extensions.insert(verified(
            serde_json::json!({ "sub": "user-1", "tenant_id": "tenant-1" }),
        ));

        let tenant = resolver.resolve(&request).await.unwrap();
        assert_eq!(tenant.id, "tenant-1");
        assert_eq!(tenant.name, "acme");
    }

    #[tokio::test]
    async fn test_jwt_resolver_single_element_array_claim() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = JwtTenantResolver::new(store, "tenants");

        let mut request = create_request("GET", "/api/users");
        request
            .extensions
            .insert(verified(serde_json::json!({ "tenants": ["tenant-2"] })));
        assert_eq!(resolver.resolve(&request).await.unwrap().id, "tenant-2");

        // Ambiguous: more than one tenant cannot pick one.
        let mut request = create_request("GET", "/api/users");
        request.extensions.insert(verified(
            serde_json::json!({ "tenants": ["tenant-1", "tenant-2"] }),
        ));
        assert!(matches!(
            resolver.resolve(&request).await,
            Err(TenantError::Invalid(_))
        ));
    }

    /// H14 regression: the raw `Authorization` header is never decoded. A
    /// forged (unsigned) token naming a tenant resolves nothing without a
    /// verified `UserContext`.
    #[tokio::test]
    async fn test_jwt_resolver_ignores_raw_authorization_header() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = JwtTenantResolver::new(store, "tenant_id");

        let token = make_jwt(&serde_json::json!({ "sub": "attacker", "tenant_id": "tenant-1" }));
        let mut request = create_request("GET", "/api/users");
        request
            .headers
            .insert("authorization", format!("Bearer {}", token));

        assert!(matches!(
            resolver.resolve(&request).await,
            Err(TenantError::ResolutionFailed(_))
        ));

        // With a verified context, the verified claim wins over the header.
        request
            .extensions
            .insert(verified(serde_json::json!({ "tenant_id": "tenant-2" })));
        assert_eq!(resolver.resolve(&request).await.unwrap().id, "tenant-2");
    }

    #[tokio::test]
    async fn test_jwt_resolver_missing_claim() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = JwtTenantResolver::new(store, "tenant_id");

        let mut request = create_request("GET", "/api/users");
        request
            .extensions
            .insert(verified(serde_json::json!({ "sub": "user-1" })));

        let result = resolver.resolve(&request).await;
        assert!(matches!(result, Err(TenantError::ResolutionFailed(_))));
    }

    #[tokio::test]
    async fn test_jwt_resolver_non_string_claim() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = JwtTenantResolver::new(store, "tenant_id");

        for bad in [
            serde_json::json!({ "tenant_id": 42 }),
            serde_json::json!({ "tenant_id": "" }),
            serde_json::json!({ "tenant_id": [] }),
        ] {
            let mut request = create_request("GET", "/api/users");
            request.extensions.insert(verified(bad.clone()));
            assert!(
                matches!(
                    resolver.resolve(&request).await,
                    Err(TenantError::Invalid(_))
                ),
                "{bad} should fail closed"
            );
        }
    }

    #[tokio::test]
    async fn test_jwt_resolver_missing_context() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = JwtTenantResolver::new(store, "tenant_id");

        let request = create_request("GET", "/api/users");
        let result = resolver.resolve(&request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_path_resolver() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = PathTenantResolver::new(store, r"^/tenants/([^/]+)", 1).unwrap();

        let request = create_request("GET", "/tenants/acme/users");

        let tenant = resolver.resolve(&request).await.unwrap();
        assert_eq!(tenant.name, "acme");
    }

    #[tokio::test]
    async fn test_path_resolver_ignores_query_string() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = PathTenantResolver::new(store, r"^/tenants/([^/]+)", 1).unwrap();

        let request = create_request("GET", "/tenants/acme/users?page=2");

        let tenant = resolver.resolve(&request).await.unwrap();
        assert_eq!(tenant.name, "acme");
    }

    #[tokio::test]
    async fn test_path_resolver_query_directly_after_tenant() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = PathTenantResolver::new(store, r"^/tenants/([^/]+)", 1).unwrap();

        let request = create_request("GET", "/tenants/acme?page=2");

        let tenant = resolver.resolve(&request).await.unwrap();
        assert_eq!(tenant.name, "acme");
    }

    #[tokio::test]
    async fn test_header_resolver_name_case_insensitive() {
        let store: Arc<dyn TenantStore> = Arc::new(MockTenantStore::new());
        let resolver = HeaderTenantResolver::trusted_internal(store, "X-Tenant-ID");

        let mut request = create_request("GET", "/api/users");
        request
            .headers
            .insert("X-TENANT-ID", "tenant-1".to_string());

        let tenant = resolver.resolve(&request).await.unwrap();
        assert_eq!(tenant.id, "tenant-1");
    }
}
