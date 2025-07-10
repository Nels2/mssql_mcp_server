import os
import re
import logging
import pymssql
from mcp.server.fastmcp import FastMCP
from typing import Union

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mssql_mcp_prologue90")

mcp = FastMCP("mssql-mcp-prologue-p90")

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
async def report_trial_balance_by_seg_ref(start_date: str, end_date: str, account_id: str) -> str:
    """
    Run the 'Trial Balance By Segment Reference' report for given date range and account ID.
    Args:
        start_date: Start date (YYYY-MM-DD).
        end_date: End date (YYYY-MM-DD).
        account_id: Account ID pattern (e.g., '7206-0000%').
    Returns:
        Results as CSV text or an error message.
    """
    config = get_db_config()
    query = """
    WITH TransactionData AS (
        SELECT 
            je.transaction_date AS [Date],
            je.journal_entry_id AS [Journal Entry],
            je.source_document_type AS [Doc. Type],
            je.source_document_id AS [Source Doc ID],
            jed.reference_number AS [Reference #],
            jed.source_reference_number AS [Source Ref #],
            jed.description AS [Description],
            je.backdated AS [Backdated],
            CASE WHEN jed.amount > 0 THEN jed.amount ELSE 0 END AS [Debits],
            CASE WHEN jed.amount < 0 THEN ABS(jed.amount) ELSE 0 END AS [Credits]
        FROM [Prologue90].[dbo].[gl_journal_entry] je
        INNER JOIN [Prologue90].[dbo].[gl_journal_entry_detail] jed
            ON je.journal_entry_id = jed.journal_entry_id
        WHERE 
            je.transaction_date BETWEEN %s AND %s
            AND jed.account_id LIKE %s
    )
    SELECT 
        [Date],
        [Journal Entry],
        [Doc. Type],
        [Source Doc ID],
        [Reference #],
        [Source Ref #],
        [Description],
        [Backdated],
        [Debits],
        [Credits],
        SUM([Debits] - [Credits]) OVER (ORDER BY [Date], [Journal Entry]) AS [Ending Balance]
    FROM TransactionData
    ORDER BY [Date], [Journal Entry];
    """
    try:
        conn = pymssql.connect(**config)
        cursor = conn.cursor()
        cursor.execute(query, (start_date, end_date, account_id))
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        result = [",".join(map(str, row)) for row in rows]
        output = "\n".join([",".join(columns)] + result)
        cursor.close()
        conn.close()
        return output
    except Exception as e:
        logger.error(f"Error executing report_trial_balance_by_seg_ref: {e}")
        return f"Error: {str(e)}"

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
async def ping() -> str:
    "Returns pong."
    return "pong"


if __name__ == "__main__":
    #mcp.run_stdio()
    mcp.run(transport='stdio')
