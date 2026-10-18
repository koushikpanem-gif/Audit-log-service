# ADR-0004: API, authentication, and input validation

- **Status:** Accepted as a supplied contract; append/query HTTP routes are
  implemented. Remaining routes belong to later actions.
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
- **Action 08 implementation:** Java API keys are UTF-8 SHA-256 hashed and
  compared with constant-time digest comparison. Dev mode has documented
  development-only credentials; configured files contain hashes and roles
  only. Writers/admins append; readers/auditors/admins query; auditors/admins
  list checkpoints. Health, OpenAPI, and the public verification key do not
  require credentials. Append JSON is byte-limited and parsed with duplicate
  key, Unicode, number-range, and depth checks before binding. Query cursors
  are versioned, HMAC-authenticated, and bound to normalized filters, order,
  and the first-page head sequence; keyset pagination uses sequence without
  OFFSET and reads each page's events and leaves in one snapshot. A cursor
  remains valid only while its API-key set is unchanged. Archive/redaction
  visibility can still change across pages, as documented by the API.
  Implemented routes are `POST /audit/events` (201), filtered
  `GET /audit/events` (inclusive `from`/`to`, default limit 50, maximum 500),
  `GET /audit/events/{eventId}` (404 for missing or archived rows),
  `GET /audit/checkpoints` (auditor/admin), `GET /audit/public-key`,
  `GET /health`, `/openapi.json`, and `/docs`. API errors use the shared
  `{error:{code,message,details}}` envelope; invalid inputs map to 422,
  request-size overflow to 413, SQL constraint conflicts to 409, and SQLite
  busy conditions to a generic 503.
