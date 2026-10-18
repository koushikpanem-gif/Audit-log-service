package com.auditlog.domain;

/**
 * One verifier diagnostic. seq and pointer are populated only when relevant; messages must never
 * contain plaintext payload values, salts or private data.
 */
public record BundleDiagnostic(BundleDiagnosticCode code, Long seq, String pointer, String message) {
}
