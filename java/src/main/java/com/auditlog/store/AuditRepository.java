package com.auditlog.store;

import java.sql.Connection;
import java.sql.SQLException;

public interface AuditRepository {

    <T> T writeTransaction(TransactionWork<T> work) throws SQLException;

    <T> T readSnapshot(TransactionWork<T> work) throws SQLException;

    @FunctionalInterface
    interface TransactionWork<T> {
        T execute(Connection connection) throws SQLException;
    }
}
