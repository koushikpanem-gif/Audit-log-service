package com.auditlog.store;

import java.sql.SQLException;

public final class StorageBusyException extends SQLException {

    public StorageBusyException(SQLException cause) {
        super("SQLite storage is busy", cause.getSQLState(), cause.getErrorCode(), cause);
    }
}
