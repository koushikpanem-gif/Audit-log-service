# Independent Python evidence verifier

`python/src/audit_log_service/verifier/` verifies `audit-export-bundle/v1` bundles and
`audit-export-set-manifest/v1` sets offline. It imports no Java code, no Starlette/Pydantic
and not the service's own canonicalization or hashing modules; it has its own strict JSON
parser and RFC 8785 serializer (`jcs.py`) and uses `cryptography` only for Ed25519.

```
python -m audit_log_service.verifier (--bundle bundle.json | --manifest set-dir/manifest.json)
    (--pinned-key-file key.b64 | --pinned-key BASE64 | --allow-self-asserted)
    [--max-bytes N] [--max-records N]
```

| Exit | Meaning |
|---|---|
| 0 | `VERIFIED` (pinned key), or `INTEGRITY_VALID_ORIGIN_UNTRUSTED` with a printed warning |
| 1 | Evidence invalid (schema, limits, signature, hashes, missing pinned key, set files) |
| 2 | Input or usage error (bad arguments, unreadable file, key not 32 raw bytes) |

## Assurance labels

- `VERIFIED`: signer key equals the out-of-band pinned raw 32-byte key (canonical Base64;
  an X.509/DER key is refused as an input error) and every check passed.
- `INTEGRITY_VALID_ORIGIN_UNTRUSTED`: only with `--allow-self-asserted`; the key came from
  the evidence, so this shows consistency, not origin.
- Neither option: `TRUSTED_KEY_REQUIRED`, exit 1.

A valid result never proves the source ledger was intact, that omitted or filtered records
do not exist, that redactions were authorized, or that upstream events were captured.
Missing disclosed leaves are counted as `undisclosedLeafCount`.

## Checks and resources

Same diagnostic codes and semantics as the Java verifier (`docs/export-bundles.md`,
`docs/export-sets.md`). Diagnostics keep the first 100 in discovery order with an exact
total. Input is capped (default 64 MiB), records capped (100000 bundle, 10,000,000 set),
leaves per record 500, nesting depth 32 (checked iteratively before parsing), chunks 100000.
Chunk names must match `chunk-NNNNNN.json`; chunks are read from the manifest directory
only, never through symlinks, with at most declared-bytes+1 bytes read; unlisted
`chunk-*.json` files are reported. Chunk chain state is carried across chunks.

## Cross-language evidence

| Direction | Fixture | Checked by |
|---|---|---|
| Python-signed -> Java | `python/tests/fixtures/python_signed`, `bundle_vectors` | `PythonInteropTests`, `BundleExportVerifierTests` |
| Java-signed -> Python | `python/tests/fixtures/java_signed` | `python/tests/test_verifier.py` |

Fixtures use the public RFC 8032 TEST 1 key (non-production). They cover Unicode (including
a supplementary-plane character and U+2028), doubles (0.1, 1e21, 1e-7), nulls, empty objects
and arrays, escaped pointers, a redacted leaf, filtered gaps, wrong keys, altered chunks,
altered manifests, dropped chunks and raw-vs-DER keys. Java-signed fixtures are frozen
because salts are random; regenerate deliberately with
`mvn -f java/pom.xml test -Dtest=PythonInteropTests -Daudit.regenerateInteropFixtures=true`.
Python-signed fixtures regenerate with `python tests/fixtures/generate_verifier_vectors.py`
(`--check` detects drift). The Python generator uses the service library and the verifier
uses its own code, so agreement between them is an independent check of JCS and hashing,
but the generator and service share an author and test key.
