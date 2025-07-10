import os
import re
import logging
import pymssql
from mcp.server.fastmcp import FastMCP
from typing import Union

# this is designed for IPA_Jumbos in Prologue (its a separate database)


# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mssql_mcp_jumbos")

mcp = FastMCP("mssql-mcp-jumbos")

def validate_table_name(table_name: str) -> str:
    """Validate and escape table name to prevent SQL injection."""
    if not re.match(r'^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)?$', table_name):
        raise ValueError(f"Invalid table name: {table_name}")
    parts = table_name.split('.')
    if len(parts) == 2:
        return f"[{parts[0]}].[{parts[1]}]"
    else:
        return f"[{table_name}]"

def get_db_config():
    """Get database configuration from environment variables."""
    server = os.getenv("MSSQL_SERVER", "localhost")
    logger.info(f"MSSQL_SERVER environment variable: {os.getenv('MSSQL_SERVER', 'NOT SET')}")
    logger.info(f"Using server: {server}")

    if server.startswith("(localdb)\\"):
        instance_name = server.replace("(localdb)\\", "")
        server = f".\\{instance_name}"
        logger.info(f"Detected LocalDB connection, converted to: {server}")

    config = {
        "server": server,
        "user": os.getenv("MSSQL_USER"),
        "password": os.getenv("MSSQL_PASSWORD"),
        "database": os.getenv("MSSQL_DATABASE"),
        "port": int(os.getenv("MSSQL_PORT", "1433")),
    }
    encrypt_str = os.getenv("MSSQL_ENCRYPT", "false")
    #config["encrypt"] = encrypt_str.lower() == "true"
    use_windows_auth = os.getenv("MSSQL_WINDOWS_AUTH", "false").lower() == "true"
    if use_windows_auth:
        if not config["database"]:
            logger.error("MSSQL_DATABASE is required")
            raise ValueError("Missing required database configuration")
        config.pop("user", None)
        config.pop("password", None)
        logger.info("Using Windows Authentication")
    else:
        if not all([config["user"], config["password"], config["database"]]):
            logger.error("Missing required database configuration. Please check environment variables:")
            logger.error("MSSQL_USER, MSSQL_PASSWORD, and MSSQL_DATABASE are required")
            raise ValueError("Missing required database configuration")
    return config

@mcp.tool()
async def execute_sql(query: str) -> str:
    """
    Execute an SQL query on the MSSQL server.
    Args:
        query: The SQL query to execute.
    Returns:
        Results as CSV text or an error message.
    """
    config = get_db_config()
    try:
        conn = pymssql.connect(**config)
        cursor = conn.cursor()
        cursor.execute(query)
        if cursor.description:  # SELECT
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            result = [",".join(map(str, row)) for row in rows]
            output = "\n".join([",".join(columns)] + result)
        else:
            conn.commit()
            affected_rows = cursor.rowcount
            output = f"Query executed successfully. Rows affected: {affected_rows}"
        cursor.close()
        conn.close()
        return output
    except Exception as e:
        logger.error(f"Error executing SQL '{query}': {e}")
        return f"Error executing query: {str(e)}"


@mcp.tool()
async def count_user_logins(user_id: str, year: Union[str, int]) -> str:
    """
    Count how many times a user_id appears in am_user_security_log in a given year.
    Args:
        user_id: User ID to search for.
        year: Year to look under.
    Returns:
        Number of appearances as string or error message.
    """
    year = str(year)
    config = get_db_config()
    sql = """
    SELECT COUNT(*) AS appearances
    FROM am_user_security_log
    WHERE user_id = %s
    AND YEAR(date_time) = %s;
    """
    try:
        conn = pymssql.connect(**config)
        cursor = conn.cursor()
        cursor.execute(sql, (user_id, year))
        count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return f"{user_id} appeared {count} times in {year}"
    except Exception as e:
        logger.error(f"Error executing count_user_logins: {e}")
        return f"Error: {str(e)}"

@mcp.tool()
async def list_sql_tables() -> str:
    """
    List all SQL Server user tables in the connected database.
    Returns:
        A CSV string of table names, or an error message.
    """
    config = get_db_config()
    sql = """
    SELECT TABLE_SCHEMA, TABLE_NAME
    FROM INFORMATION_SCHEMA.TABLES
    WHERE TABLE_TYPE = 'BASE TABLE'
    ORDER BY TABLE_SCHEMA, TABLE_NAME;
    """
    try:
        conn = pymssql.connect(**config)
        cursor = conn.cursor()
        cursor.execute(sql)
        tables = cursor.fetchall()
        cursor.close()
        conn.close()
        if not tables:
            return "No tables found in this database."
        # Format as CSV or nice table
        lines = ["Schema,Table"]
        for schema, name in tables:
            lines.append(f"{schema},{name}")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error listing tables: {e}")
        return f"Error listing tables: {str(e)}"

@mcp.tool()
async def read_table_preview(table_name: str) -> str:
    """
    Preview up to 100 rows from a specified SQL Server table.
    Args:
        table_name: Name of the table to preview (optionally schema-qualified, e.g., 'dbo.my_table').
    Returns:
        A CSV string of up to 100 rows, or an error message.
    """
    config = get_db_config()
    try:
        # Validate the table name to prevent SQL injection
        safe_table = validate_table_name(table_name)
        conn = pymssql.connect(**config)
        cursor = conn.cursor()
        cursor.execute(f"SELECT TOP 100 * FROM {safe_table}")
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        if not rows:
            return "No data found in this table."
        result = [",".join(map(str, row)) for row in rows]
        return "\n".join([",".join(columns)] + result)
    except Exception as e:
        logger.error(f"Error reading table '{table_name}': {e}")
        return f"Error reading table '{table_name}': {str(e)}"

@mcp.tool()
async def ping() -> str:
    "Returns pong."
    return "pong"


if __name__ == "__main__":
    #mcp.run_stdio()
    mcp.run(transport='stdio')
