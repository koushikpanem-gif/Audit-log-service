package com.auditlog.verify;

/**
 * One diagnostic. Messages never contain stored business values; {@code pointer} is an
 * RFC 6901 payload path when the problem is localized to one leaf.
 */
public record Violation(ViolationType type, Long seq, String pointer, String message) {
}
