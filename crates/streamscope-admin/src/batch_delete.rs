//! The batched delete every purge runs: one statement, re-run until it stops
//! matching rows, with a pause between batches so no lock is held long. It runs
//! on a connection one of the `db` doors handed out.

use crate::db::tenant::Scoped;

/// Delete in batches until the statement stops matching rows.
///
/// `sql` is the whole statement, so it is `&'static str`: it may only ever be a
/// literal written in the code. A `String` assembled at runtime cannot be passed,
/// which is what keeps this — the widest SQL-taking signature in the crate — from
/// becoming an injection sink. The cutoff and batch size are bound.
pub(crate) async fn batch_delete_conn(
    conn: &mut Scoped,
    sql: &'static str,
    cutoff: &chrono::DateTime<chrono::Utc>,
    batch_size: i64,
) -> Result<u64, sqlx::Error> {
    // A batch of 0 would match nothing forever and never end the loop.
    let batch_size = batch_size.max(1);
    let mut total: u64 = 0;
    loop {
        let result = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(cutoff)
            .bind(batch_size)
            .execute(&mut *conn)
            .await?;

        let deleted = result.rows_affected();
        total += deleted;
        if deleted < batch_size as u64 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(crate::settings::admin_settings().retention_batch_sleep_ms)).await;
    }
    Ok(total)
}
