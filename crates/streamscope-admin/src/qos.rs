//! Loading the tenant's QoS classes for the config snapshot.
//!
//! Suppressed classes are left out: the proxy treats a key or workspace pointing
//! at a class it does not know as naming none, which is exactly what a deleted
//! class should mean.

use std::collections::HashMap;

use streamscope_core::config::qos::{QosClass, QosTable};
use uuid::Uuid;
use crate::db::tenant::Scoped;

/// Every live class, the tenant default, each workspace's class and weight, and
/// the classes each route target restricts itself to.
pub(crate) async fn load_qos_table(
    conn: &mut Scoped,
) -> Result<QosTable, sqlx::Error> {
    let class_rows: Vec<(Uuid, String, i32, bool, Option<i32>, bool)> = sqlx::query_as(
        "SELECT id, name, rank, sheddable, queue_ttl_ms, is_default \
         FROM qos_classes WHERE NOT suppressed",
    )
    .fetch_all(&mut *conn)
    .await?;

    let mut classes: HashMap<Uuid, QosClass> = HashMap::new();
    let mut default_class = None;
    for (id, name, rank, sheddable, queue_ttl_ms, is_default) in class_rows {
        if is_default {
            default_class = Some(id);
        }
        classes.insert(
            id,
            QosClass {
                id,
                name,
                rank,
                sheddable,
                queue_ttl_ms: queue_ttl_ms.and_then(|v| u32::try_from(v).ok()).filter(|v| *v > 0),
            },
        );
    }

    let workspace_rows: Vec<(Uuid, Option<Uuid>, i32)> =
        sqlx::query_as("SELECT id, qos_class_id, fairness_weight FROM workspaces")
            .fetch_all(&mut *conn)
            .await?;
    let mut workspace_class = HashMap::new();
    let mut workspace_weight = HashMap::new();
    for (id, class_id, weight) in workspace_rows {
        if let Some(class_id) = class_id.filter(|c| classes.contains_key(c)) {
            workspace_class.insert(id, class_id);
        }
        // Only what differs from the default is worth shipping.
        let weight = u32::try_from(weight).unwrap_or(1).max(1);
        if weight != 1 {
            workspace_weight.insert(id, weight);
        }
    }

    let route_rows: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT route_id, qos_class_id FROM route_qos_classes")
            .fetch_all(&mut *conn)
            .await?;
    let mut route_classes: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for (route_id, class_id) in route_rows {
        if classes.contains_key(&class_id) {
            route_classes.entry(route_id).or_default().push(class_id);
        }
    }

    Ok(QosTable { classes, default_class, workspace_class, workspace_weight, route_classes })
}
