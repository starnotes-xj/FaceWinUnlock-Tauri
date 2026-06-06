//! signCount 持久化（SQLite）
//!
//! WebAuthn 规范要求签名计数器（signCount）单调递增。
//! RP 可据此检测凭据克隆攻击。
//!
//! 每成功生成一个 assertion，对应 credentialId 的
//! signCount 加 1 并持久化到数据库。

use rusqlite::{params, Connection};
use std::path::Path;

/// 确保 sign_count 表存在
pub fn ensure_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passkey_sign_count (
            credential_id TEXT NOT NULL PRIMARY KEY,
            counter       INTEGER NOT NULL DEFAULT 0,
            last_used     TEXT DEFAULT (datetime('now', 'localtime'))
        )",
        [],
    )?;
    Ok(())
}

/// 获取指定凭据的当前签名计数
pub fn get_sign_count(db_path: &Path, credential_id: &str) -> u32 {
    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let _ = ensure_table(&conn);

    conn.query_row(
        "SELECT counter FROM passkey_sign_count WHERE credential_id = ?1",
        params![credential_id],
        |row| row.get::<_, i64>(0),
    )
    .ok()
    .map(|v| v as u32)
    .unwrap_or(0)
}

/// 递增指定凭据的签名计数并返回新值
pub fn increment_sign_count(db_path: &Path, credential_id: &str) -> u32 {
    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(_) => return 1,
    };
    let _ = ensure_table(&conn);

    let current = get_sign_count(db_path, credential_id);
    let next = current.wrapping_add(1);

    let _ = conn.execute(
        "INSERT INTO passkey_sign_count (credential_id, counter, last_used)
         VALUES (?1, ?2, datetime('now', 'localtime'))
         ON CONFLICT(credential_id) DO UPDATE SET
             counter = ?2,
             last_used = datetime('now', 'localtime')",
        params![credential_id, next as i64],
    );

    next
}
