# ADR-0004: API, authentication, and input validation

- **Status:** Accepted as a supplied contract; implementation pending.
- **Context:** Writers, readers, auditors and administrators need distinct
  capabilities without trusting request-supplied identity or source.
- **Decision:** Authenticate with `X-API-Key`; persist only key hashes and
  principal roles, compare hashes in constant time, derive source from the
  authenticated principal, and reserve system event types/source for internal
  use. Apply the specified roles and routes. Use the common error envelope and
  status semantics; never disclose stack traces or sensitive values. Enforce
  request/payload/depth/leaf limits, strict envelope fields, valid UTC times,
  future-skew limit, finite retention and positive bounded configuration.
  Provide health/public key, OpenAPI, event, verify, export, checkpoint,
  redaction and archive routes; never expose event PUT/PATCH/DELETE.
- **Consequences:** Local development may create a restrictive key, but
  production requires an existing valid private key and API-key file. Key
  material is never silently overwritten; sample credentials must be clearly
  development-only. API-key configuration is a principal-keyed JSON object
  containing only a lowercase SHA-256 `keyHash` and a non-empty array of
  distinct recognized `roles` (`writer`, `reader`, `auditor`, `admin`); raw
  API keys are not accepted in the file. Runtime names and bounds are listed
  in [configuration and signing](../configuration-and-signing.md).
