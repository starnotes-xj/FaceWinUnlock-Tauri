use std::{path::Path, time::Duration};

use rusqlite::{Connection, TransactionBehavior};
use tauri_plugin_log::log::info;

use crate::credential_protection::{
    is_protected_credential, load_credential_entropy, protect_with_entropy, unprotect_with_entropy,
    CREDENTIAL_PREFIX,
};
use crate::zeroization::{zeroize_bytes, zeroize_string};

fn migrate_connection(conn: &mut Connection, entropy: &[u8]) -> Result<usize, String> {
    let has_faces_table = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='faces'",
            [],
            |_| Ok(()),
        )
        .is_ok();
    if !has_faces_table {
        return Ok(0);
    }

    conn.execute_batch("PRAGMA secure_delete = ON;")
        .map_err(|error| format!("启用安全删除失败: {error}"))?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("开始凭据迁移事务失败: {error}"))?;
    let values = {
        let mut statement = tx
            .prepare("SELECT id, user_pwd FROM faces")
            .map_err(|error| format!("读取旧凭据失败: {error}"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| format!("读取旧凭据失败: {error}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("读取旧凭据失败: {error}"))?
    };

    let mut migrated = 0;
    let mut migration_error = None;
    for (id, mut stored) in values {
        if migration_error.is_some() {
            zeroize_string(&mut stored);
            continue;
        }

        let result = (|| -> Result<bool, String> {
            if is_protected_credential(&stored) {
                let encoded = stored
                    .strip_prefix(CREDENTIAL_PREFIX)
                    .expect("prefix checked above");
                let mut plaintext = unprotect_with_entropy(encoded, entropy)
                    .map_err(|error| format!("验证已保护凭据失败（记录 {id}）: {error}"))?;
                zeroize_string(&mut plaintext);
                Ok(false)
            } else {
                let protected = protect_with_entropy(&stored, entropy)?;
                tx.execute(
                    "UPDATE faces SET user_pwd = ?1 WHERE id = ?2",
                    rusqlite::params![protected, id],
                )
                .map_err(|error| format!("更新受保护凭据失败（记录 {id}）: {error}"))?;
                Ok(true)
            }
        })();
        zeroize_string(&mut stored);
        match result {
            Ok(true) => migrated += 1,
            Ok(false) => {}
            Err(error) => migration_error = Some(error),
        }
    }
    if let Some(error) = migration_error {
        return Err(error);
    }
    tx.commit()
        .map_err(|error| format!("提交凭据迁移事务失败: {error}"))?;

    if migrated > 0 {
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
            .map_err(|error| format!("清理旧凭据数据库页失败: {error}"))?;
    }
    Ok(migrated)
}

fn migrate_database(path: &Path) -> Result<usize, String> {
    if !path.exists() {
        return Ok(0);
    }
    let mut conn =
        Connection::open(path).map_err(|error| format!("打开凭据数据库失败: {error}"))?;
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(|error| format!("设置数据库等待时间失败: {error}"))?;
    let has_faces_table = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='faces'",
            [],
            |_| Ok(()),
        )
        .is_ok();
    if !has_faces_table {
        return Ok(0);
    }
    let (has_records, has_protected): (bool, bool) = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM faces), EXISTS(SELECT 1 FROM faces WHERE substr(user_pwd, 1, length(?1)) = ?1)",
            [CREDENTIAL_PREFIX],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| format!("检查凭据格式失败: {error}"))?;
    if !has_records {
        return Ok(0);
    }

    let entropy = match load_credential_entropy(false)? {
        Some(entropy) => entropy,
        None if has_protected => {
            return Err("受保护凭据存在，但注册表密钥缺失；为避免丢失凭据，已停止迁移".to_string())
        }
        None => load_credential_entropy(true)?.ok_or_else(|| "无法建立凭据密钥".to_string())?,
    };
    let migration_result = migrate_connection(&mut conn, &entropy);
    let mut entropy = entropy;
    zeroize_bytes(&mut entropy);
    let migrated = migration_result?;
    if migrated > 0 {
        info!("已迁移并保护 {} 条 Windows 登录凭据", migrated);
    }
    Ok(migrated)
}

#[tauri::command]
pub fn protect_credential(mut password: String) -> Result<String, String> {
    let result = (|| {
        let mut entropy =
            load_credential_entropy(true)?.ok_or_else(|| "无法建立凭据密钥".to_string())?;
        let result = protect_with_entropy(&password, &entropy);
        zeroize_bytes(&mut entropy);
        result
    })();
    zeroize_string(&mut password);
    result
}

#[tauri::command]
pub fn migrate_face_credentials() -> Result<usize, String> {
    migrate_database(&crate::ROOT_DIR.join("database.db"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ENTROPY: &[u8] = b"FaceWinUnlock test entropy";

    #[test]
    fn legacy_credentials_migrate_atomically_and_are_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE faces (id INTEGER PRIMARY KEY, user_pwd TEXT NOT NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO faces (id, user_pwd) VALUES (1, 'legacy-secret')",
            [],
        )
        .unwrap();

        assert_eq!(migrate_connection(&mut conn, TEST_ENTROPY).unwrap(), 1);
        let stored: String = conn
            .query_row("SELECT user_pwd FROM faces WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(is_protected_credential(&stored));
        assert_eq!(
            unprotect_with_entropy(
                stored.strip_prefix(CREDENTIAL_PREFIX).unwrap(),
                TEST_ENTROPY
            )
            .unwrap(),
            "legacy-secret"
        );
        assert_eq!(migrate_connection(&mut conn, TEST_ENTROPY).unwrap(), 0);
    }

    #[test]
    fn malformed_protected_credential_rolls_back_prior_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE faces (id INTEGER PRIMARY KEY, user_pwd TEXT NOT NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO faces (id, user_pwd) VALUES (1, 'legacy-secret'), (2, 'FWDP1:invalid')",
            [],
        )
        .unwrap();

        assert!(migrate_connection(&mut conn, TEST_ENTROPY).is_err());
        let stored: String = conn
            .query_row("SELECT user_pwd FROM faces WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(stored, "legacy-secret");
    }
}
