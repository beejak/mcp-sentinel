"""
Context flooding vulnerability fixtures — patterns that SHOULD be detected.

Each function represents a real attack surface: unbounded reads, uncapped
directory walks, queries without LIMIT, and list tools missing pagination.
"""

# =============================================================================
# VULNERABLE PATTERNS — should be detected
# =============================================================================

import os
from pathlib import Path


# ---- Unbounded file reads ----

def tool_read_file_unbounded(path: str) -> str:
    """MCP tool: reads entire file without size cap."""
    return open(path).read()  # VULNERABLE: no size limit


def tool_read_config_unbounded(config_path: str) -> str:
    """Returns full config file content."""
    return Path(config_path).read_text()  # VULNERABLE: no size limit


async def tool_read_log_async(log_file: str) -> str:
    """Reads log file for analysis."""
    import aiofiles  # VULNERABLE: unbounded async read flagged at import line
    async with aiofiles.open(log_file) as f:
        return await f.read()


# ---- Unbounded directory walks ----

def tool_list_all_files(directory: str) -> list:
    """Lists every file recursively — no depth limit."""
    all_files = []
    for root, dirs, files in os.walk(directory):  # VULNERABLE: unbounded walk
        for f in files:
            all_files.append(os.path.join(root, f))
    return all_files


def tool_find_python_files(base_dir: str) -> list:
    """Finds all Python files recursively."""
    return list(Path(base_dir).rglob("*.py"))  # VULNERABLE: unbounded rglob


def tool_glob_all_configs(base: str) -> list:
    """Returns all config files anywhere under base."""
    import glob
    return glob.glob(f"{base}/**/*.yaml")  # VULNERABLE: ** glob without limit


# ---- Database queries without LIMIT ----

def tool_get_all_users(db) -> list:
    """Returns all users from the database."""
    cursor = db.execute("SELECT * FROM users")  # VULNERABLE: no LIMIT
    return cursor.fetchall()  # VULNERABLE: fetchall


def tool_search_records(db, query: str) -> list:
    cursor = db.execute(f"SELECT * FROM records WHERE name LIKE '%{query}%'")
    return cursor.fetchall()  # VULNERABLE: fetchall + no LIMIT


def tool_get_events(session) -> list:
    """SQLAlchemy: fetches all events."""
    return session.query(Event).all()  # VULNERABLE: .all() without limit


# ---- Missing pagination on list tools ----

def list_documents(user_id: str) -> list:  # VULNERABLE: no limit/cursor param
    """MCP tool: returns all documents for a user."""
    return db.query("SELECT * FROM documents WHERE user_id = ?", user_id).fetchall()


async def get_all_messages(channel_id: str) -> list:  # VULNERABLE: no pagination
    """Returns all messages in a channel."""
    return await db.fetch("SELECT * FROM messages WHERE channel_id = $1", channel_id)


def fetch_all_records(table: str) -> list:  # VULNERABLE: name signals unbounded
    """Returns every record in the given table."""
    return db.execute(f"SELECT * FROM {table}").fetchall()


# =============================================================================
# SAFE PATTERNS — should NOT be detected
# =============================================================================


def safe_read_with_limit(path: str, max_bytes: int = 65536) -> str:
    """Reads file up to max_bytes."""
    return open(path).read(max_bytes)  # SAFE: size capped


def safe_read_text_bounded(path: str) -> str:
    """Reads first 64KB of a file."""
    with open(path) as f:
        return f.read(65536)  # SAFE


def safe_list_files_limited(directory: str, max_files: int = 100) -> list:
    """Lists files up to max_files."""
    results = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            results.append(os.path.join(root, f))
            if len(results) >= max_files:
                return results
    return results


def safe_get_users_paginated(db, limit: int = 50, offset: int = 0) -> list:
    """Returns paginated users."""
    return db.execute(
        "SELECT * FROM users LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()  # SAFE: LIMIT applied before fetchall


def safe_list_documents(user_id: str, limit: int = 50, cursor: str = None) -> dict:
    """Paginated document listing with cursor."""
    rows = db.query(
        "SELECT * FROM documents WHERE user_id = ? LIMIT ?", user_id, limit
    ).fetchall()
    return {"items": rows, "next_cursor": rows[-1]["id"] if rows else None}
