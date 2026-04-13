"""
Detección error-based SQLi a partir del cuerpo de la respuesta.
Evita usar "syntax error" aislado sin contexto SQL.
"""
from __future__ import annotations

# Fragmentos de alta confianza (motores, drivers, mensajes típicos)
SQLI_ERROR_FRAGMENTS: tuple[str, ...] = (
    # MySQL / MariaDB
    "you have an error in your sql syntax",
    "mysql server version for the right syntax",
    "warning: mysql",
    "mysqli_",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "supplied argument is not a valid mysql",
    "column count doesn't match",
    "unknown column",
    "check the manual that corresponds to your mysql",
    "valid mysql result",
    # PostgreSQL
    "postgresql",
    "postgres query failed",
    "pg_query(",
    "pg_exec(",
    "unterminated quoted string at or near",
    "syntax error at or near",
    "invalid input syntax for type",
    "warning: pg_",
    # Microsoft SQL Server
    "microsoft ole db provider for sql server",
    "microsoft ole db provider for odbc drivers",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "sql server native client",
    "sqlserver jdbc driver",
    "[sql server]",
    "odbc sql server driver",
    "microsoft sql server",
    "could not prepare statement",
    # Oracle
    "ora-01756",
    "ora-00933",
    "ora-00921",
    "ora-00936",
    "quoted string not properly terminated",
    "oracle error",
    "oracle driver",
    "oracle oci",
    # SQLite
    "sqlite3::",
    "sqlite3.operationalerror",
    "sqlite exception",
    'near "',
    "near '",
    # ODBC / PDO / JDBC
    "sqlstate[",
    "pdoexception",
    "[microsoft][odbc",
    "odbc driver manager",
    "jdbc sql",
    # Genéricos con señal SQL
    "sql syntax",
    "query failed",
    "unterminated quoted string",
    "invalid sql",
    "sql command",
)

# Si aparece "syntax error", exigir contexto para no confundir con JSON/JS
_SYNTAX_ERROR_SQL_CONTEXT: tuple[str, ...] = (
    "sql",
    "query",
    "near",
    "column",
    "table",
    "from",
    "where",
    "ora-",
    "sqlite",
    "mysql",
    "postgres",
    "mssql",
    "syntax error at",
    "incorrect syntax",
    "pg_",
    "tsql",
    "pl/sql",
)


def is_sqli_error_response(text: str) -> bool:
    if not isinstance(text, str) or not text.strip():
        return False
    lowered = text.lower()
    if any(frag in lowered for frag in SQLI_ERROR_FRAGMENTS):
        return True
    if "syntax error" in lowered:
        return any(ctx in lowered for ctx in _SYNTAX_ERROR_SQL_CONTEXT)
    return False
