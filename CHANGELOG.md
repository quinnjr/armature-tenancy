# Changelog — `armature-tenancy`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Fixed

- **Breaking:** `Tenant::with_schema` validates the identifier and returns a `Result`. It was forwarded verbatim to `SET search_path`, which is how tenant isolation gets bypassed.
- Path-based tenant resolution matches `path_only()`; any request carrying a query string previously failed to resolve.

### Changed — `0.3.0` → `0.3.1`

- Migrated onto `armature-core` `0.8`'s `Bytes`-backed request and response types. No behavior change beyond what that migration implies; see [`armature-core/CHANGELOG.md`](../armature-core/CHANGELOG.md).

## [0.4.1] - 2026-08-04

### Fixed

- Requirements on sibling armature crates name a minor instead of `0`. Under
  Cargo's 0.x rules `version = "0"` matches any release ever made, and edition
  2024 selects the MSRV-aware resolver, so a consumer declaring an older
  `rust-version` was handed the oldest version satisfying it — resolving
  `armature-core = "0"` on Rust 1.89 produced `armature-core 0.2.3` while an
  explicit `armature-core = "0.8"` elsewhere in the same graph pulled 0.8.2.
  Two copies of core, and a build failing on symbols the older one lacks. Each
  0.x minor in this family is a breaking change, so the requirement now names
  one. No API change.
