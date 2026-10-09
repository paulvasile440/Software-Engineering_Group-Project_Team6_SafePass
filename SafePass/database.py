import sqlite3
from pathlib import Path
from typing import Optional

DB_NAME = "safepass.db"


class Database:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or str(Path(__file__).with_name(DB_NAME))
        self._create_tables()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _create_tables(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS password_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_encrypted TEXT NOT NULL,
                    notes_encrypted TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def get_setting(self, key: str):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key = ?",
                (key,),
            ).fetchone()
            return row[0] if row else None

    def set_setting(self, key: str, value: bytes):
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, value),
            )

    def has_master_password(self) -> bool:
        return self.get_setting("master_salt") is not None and self.get_setting("master_verifier") is not None

    def add_record(self, service: str, username: str, password_encrypted: str, notes_encrypted: str):
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO password_records
                (service, username, password_encrypted, notes_encrypted)
                VALUES (?, ?, ?, ?)
            """, (service, username, password_encrypted, notes_encrypted))

    def update_record(self, record_id: int, service: str, username: str, password_encrypted: str, notes_encrypted: str):
        with self._connect() as conn:
            conn.execute("""
                UPDATE password_records
                SET service = ?, username = ?, password_encrypted = ?, notes_encrypted = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (service, username, password_encrypted, notes_encrypted, record_id))

    def delete_record(self, record_id: int):
        with self._connect() as conn:
            conn.execute("DELETE FROM password_records WHERE id = ?", (record_id,))

    def list_records(self):
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT id, service, username, password_encrypted, notes_encrypted,
                       created_at, updated_at
                FROM password_records
                ORDER BY service COLLATE NOCASE, username COLLATE NOCASE
            """).fetchall()
            return rows

    def get_record(self, record_id: int):
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            return conn.execute("""
                SELECT id, service, username, password_encrypted, notes_encrypted,
                       created_at, updated_at
                FROM password_records
                WHERE id = ?
            """, (record_id,)).fetchone()
