//! `every_on_conflict_target_is_a_key_of_its_table`: an `INSERT … ON CONFLICT
//! (cols)` names a unique key of the table it inserts into, or PostgreSQL
//! refuses the statement at run time ("there is no unique or exclusion
//! constraint matching the ON CONFLICT specification") — on whatever path first
//! runs it, which a reshaped key can leave to a rarely-taken branch.
//!
//! The keys are read from `migrations/001_init.sql` (every `PRIMARY KEY (…)`,
//! `UNIQUE (…)`, `UNIQUE NULLS NOT DISTINCT (…)` and `CREATE UNIQUE INDEX … ON
//! t (…)`), the targets from every `.rs` file of the crate. Order within a
//! target does not matter to PostgreSQL, so neither does it here. A partial
//! index is a key only for a target that restates a predicate (`ON CONFLICT
//! (…) WHERE …`) — without one PostgreSQL does not infer it; that the predicate
//! is the index's own is not checked.

use std::collections::{BTreeSet, HashMap};

type Key = BTreeSet<String>;

/// A unique key: its columns, and whether it is a partial index.
#[derive(Debug, PartialEq, Eq)]
struct UniqueKey {
    cols: Key,
    partial: bool,
}

/// The unique keys of each table the migration declares.
fn keys(sql: &str) -> HashMap<String, Vec<UniqueKey>> {
    let mut out: HashMap<String, Vec<UniqueKey>> = HashMap::new();
    let cols = |list: &str| -> Key {
        list.split(',')
            .map(|c| c.trim().trim_matches('"').to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect()
    };
    // CREATE TABLE name ( … ); — scan its body for PRIMARY KEY / UNIQUE lists
    // and column-level PRIMARY KEY / UNIQUE.
    let mut rest = sql;
    while let Some(i) = rest.find("CREATE TABLE ") {
        rest = &rest[i + "CREATE TABLE ".len()..];
        let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        let Some(open) = rest.find('(') else { break };
        let body_start = open + 1;
        let mut depth = 1;
        let mut end = body_start;
        for (k, ch) in rest[body_start..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = body_start + k;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &rest[body_start..end];
        let entry = out.entry(name.to_ascii_lowercase()).or_default();
        for line in body.lines() {
            let l = line.trim();
            let l = l.split("--").next().unwrap_or("").trim();
            for marker in ["PRIMARY KEY (", "UNIQUE (", "UNIQUE NULLS NOT DISTINCT ("] {
                if let Some(p) = l.find(marker) {
                    let tail = &l[p + marker.len()..];
                    if let Some(close) = tail.find(')') {
                        entry.push(UniqueKey { cols: cols(&tail[..close]), partial: false });
                    }
                }
            }
            // `col TYPE … PRIMARY KEY` / `… UNIQUE` on the column itself.
            let first = l.split_whitespace().next().unwrap_or("");
            if !first.is_empty()
                && !["PRIMARY", "UNIQUE", "FOREIGN", "CONSTRAINT", "CHECK"].contains(&first)
                && (l.contains(" PRIMARY KEY") && !l.contains("PRIMARY KEY (")
                    || l.contains(" UNIQUE") && !l.contains("UNIQUE (") && !l.contains("UNIQUE NULLS NOT DISTINCT ("))
            {
                entry.push(UniqueKey { cols: cols(first), partial: false });
            }
        }
        rest = &rest[end..];
    }
    // CREATE UNIQUE INDEX name ON table (cols) …
    let mut rest = sql;
    while let Some(i) = rest.find("CREATE UNIQUE INDEX ") {
        rest = &rest[i..];
        let stmt = &rest[..rest.find(';').unwrap_or(rest.len())];
        if let Some(on) = stmt.find(" ON ") {
            let after = stmt[on + 4..].trim_start();
            let table: String = after.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            if let Some(open) = after.find('(')
                && let Some(close) = after[open..].find(')')
            {
                let partial = after[open + close..].contains("WHERE");
                out.entry(table.to_ascii_lowercase())
                    .or_default()
                    .push(UniqueKey { cols: cols(&after[open + 1..open + close]), partial });
            }
        }
        rest = &rest["CREATE UNIQUE INDEX ".len()..];
    }
    out
}

/// `src` with every `ON CONFLICT {NAME}` — a target spliced into a `format!`
/// from a `const NAME: &str = "…"` of the same file — replaced by that constant's
/// text, so the spliced targets are checked like the literal ones. A name with
/// no such constant is returned as an error: the scan must not skip a target it
/// cannot read.
fn inline_spliced_targets(src: &str) -> Result<String, String> {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(i) = rest.find("ON CONFLICT {") {
        let after = &rest[i + "ON CONFLICT {".len()..];
        let Some(close) = after.find('}') else { break };
        let name = &after[..close];
        let decl = format!("const {name}: &str =");
        let value = src
            .find(&decl)
            .and_then(|d| {
                let tail = &src[d + decl.len()..];
                let open = tail.find('"')?;
                let end = tail[open + 1..].find('"')?;
                Some(&tail[open + 1..open + 1 + end])
            })
            .ok_or_else(|| format!("ON CONFLICT {{{name}}} names no `const {name}: &str` in the same file"))?;
        out.push_str(&rest[..i]);
        out.push_str("ON CONFLICT ");
        out.push_str(value);
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Every `INSERT INTO t … ON CONFLICT (cols) [WHERE …]` in `src`: (table,
/// target, whether it restates a predicate, where).
fn targets(src: &str, file: &str) -> Vec<(String, Key, bool, String)> {
    let mut out = Vec::new();
    let mut search = 0;
    while let Some(i) = src[search..].find("ON CONFLICT (") {
        let at = search + i;
        search = at + 1;
        let tail = &src[at + "ON CONFLICT (".len()..];
        // A target may itself hold parentheses (an expression); read to the
        // matching close.
        let mut depth = 1;
        let mut end = 0;
        for (k, ch) in tail.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = k;
                        break;
                    }
                }
                _ => {}
            }
        }
        let target: Key = tail[..end]
            .split(',')
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect();
        // The table: the nearest `INSERT INTO <name>` before the clause.
        let before = &src[..at];
        let Some(ins) = before.rfind("INSERT INTO ") else { continue };
        let table: String = before[ins + "INSERT INTO ".len()..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        // `WHERE` right after the target, across the line continuations a
        // Rust string literal spells as a backslash and indentation.
        let rest: String = tail[end + 1..].chars().take(64).collect();
        let predicate = rest
            .trim_start_matches(|c: char| c.is_whitespace() || c == '\\')
            .starts_with("WHERE");
        let line = src[..at].matches('\n').count() + 1;
        out.push((table.to_ascii_lowercase(), target, predicate, format!("{file}:{line}")));
    }
    out
}

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("a source directory") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_on_conflict_target_is_a_key_of_its_table() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Every migration, in order: a later one adds tables (and keys) of its own.
    let mut migrations: Vec<_> = std::fs::read_dir(root.join("../../migrations"))
        .expect("the migrations directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    migrations.sort();
    assert!(!migrations.is_empty(), "no migration was read");
    let sql: String = migrations
        .iter()
        .map(|p| std::fs::read_to_string(p).expect("a migration"))
        .collect::<Vec<_>>()
        .join("\n");
    let keys = keys(&sql);
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let this = file!().rsplit('/').next().unwrap_or_default();
    let mut seen = 0;
    let mut wrong = Vec::new();
    for f in files {
        if f.file_name().is_some_and(|n| n == this) {
            continue;
        }
        let src = std::fs::read_to_string(&f).expect("a source file");
        let src = match inline_spliced_targets(&src) {
            Ok(src) => src,
            Err(e) => {
                wrong.push(format!("{}: {e}", f.display()));
                continue;
            }
        };
        for (table, target, predicate, at) in targets(&src, &f.display().to_string()) {
            seen += 1;
            let matches = |k: &UniqueKey| k.cols == target && (predicate || !k.partial);
            if !keys.get(&table).is_some_and(|ks| ks.iter().any(matches)) {
                wrong.push(format!(
                    "{at}: ON CONFLICT {target:?}{} is no key of `{table}` (keys: {:?})",
                    if predicate { " WHERE …" } else { "" },
                    keys.get(&table)
                ));
            }
        }
    }
    // Positive control: the scan found the crate's upserts (dozens of them).
    assert!(seen > 40, "only {seen} ON CONFLICT targets found — the scan is wrong");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_key_reader_sees_every_declaration_form() {
    let sql = "CREATE TABLE t (\n    tenant_id UUID NOT NULL,\n    id UUID NOT NULL,\n    code TEXT UNIQUE,\n    name TEXT,\n    tag TEXT,\n    PRIMARY KEY (tenant_id, id),\n    UNIQUE (tenant_id, name),\n    UNIQUE NULLS NOT DISTINCT (tenant_id, tag)\n);\nCREATE UNIQUE INDEX idx_t_x ON t (tenant_id, code) WHERE code IS NOT NULL;\nCREATE TABLE g (\n    token TEXT PRIMARY KEY\n);\n";
    let k = keys(sql);
    let set = |cols: &[&str]| cols.iter().map(|c| c.to_string()).collect::<Key>();
    let key = |cols: &[&str], partial: bool| UniqueKey { cols: set(cols), partial };
    let t = &k["t"];
    for want in [
        key(&["tenant_id", "id"], false),
        key(&["tenant_id", "name"], false),
        key(&["tenant_id", "tag"], false),
        key(&["code"], false),
        key(&["tenant_id", "code"], true),
    ] {
        assert!(t.contains(&want), "{want:?} missing from {t:?}");
    }
    assert!(k["g"].contains(&key(&["token"], false)));
    let src = "sqlx::query(\"INSERT INTO t (a) VALUES ($1) ON CONFLICT (id, tenant_id) DO NOTHING\")";
    let found = targets(src, "x.rs");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, "t");
    assert_eq!(found[0].1, set(&["tenant_id", "id"]));
    assert!(!found[0].2, "no predicate follows the target");
    // A target spliced from a constant is read through it, its predicate aside.
    let spliced = "const T_KEY: &str = \"(tenant_id, code) WHERE code IS NOT NULL\";\nformat!(\"INSERT INTO t (code) VALUES ($1) ON CONFLICT {T_KEY} DO NOTHING\")";
    let found = targets(&inline_spliced_targets(spliced).expect("the constant is found"), "x.rs");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, set(&["tenant_id", "code"]));
    assert!(found[0].2, "the predicate after the target is seen");
    let continued = "\"INSERT INTO t (code) VALUES ($1) ON CONFLICT (tenant_id, code) \\\n                 WHERE code IS NOT NULL DO NOTHING\"";
    assert!(targets(continued, "x.rs")[0].2, "a predicate on the next literal line is seen");
    assert!(inline_spliced_targets("format!(\"ON CONFLICT {NOWHERE} DO NOTHING\")").is_err());
}
