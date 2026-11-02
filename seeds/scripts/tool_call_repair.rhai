// name = "tool_call_repair"
// description = "Repairs semantically malformed tool-call arguments from models that emit stringified JSON — recursively coerces a stringified array or object back into a real array or object, and string true/false into a real boolean. An operator-editable rules table (empty by default) adds per-tool defaults, enum whitelists, and parameter removal. JSON syntax repair (trailing commas, unclosed brackets) is handled separately by the gateway healing_enabled setting. Disabled by default."
// phase = "response"
// scope = "tool"
// priority = 100
// enabled = false

fn repair_rules() {
    // Operator-editable per-tool repair rules. Ships empty — add one entry per
    // tool you want to repair. Each tool name maps to a rule object with three
    // optional fields:
    //   defaults — #{ param: value }      fill the param when missing or null
    //   enums    — #{ param: [allowed] }  drop the param if its value is not listed
    //   remove   — [ param, param ]       always strip these params
    //
    // Example (uncomment and adapt to your own tools):
    //   #{
    //       "my_search_tool": #{
    //           defaults: #{ "max_results": 10, "safe_mode": true },
    //           enums:    #{ "sort": ["relevance", "date"] },
    //           remove:   ["internal_trace_id"]
    //       }
    //   }
    #{}
}

// Recursively coerce stringified JSON values back to real types. A string that
// looks like a JSON array/object and parses cleanly is unwrapped; "true" and
// "false" become booleans. Everything else is returned unchanged. Maps and
// arrays are rebuilt into fresh containers so there is no aliasing.
fn coerce_value(v, depth) {
    // Bound recursion well under the engine's call-level limit (32). Real
    // tool-call arguments are never nested anywhere near this deep — the cap
    // is a pathological-input guard, not something a genuine payload reaches.
    if depth > 24 {
        return v;
    }
    let t = type_of(v);
    if t == "string" {
        // `trim()` mutates in place, so trim a copy and leave `v` pristine —
        // a plain string value must be returned unchanged.
        let probe = v;
        probe.trim();
        if probe.starts_with("[") || probe.starts_with("{") {
            let parsed = parse_json(probe);
            let pt = type_of(parsed);
            if pt == "array" || pt == "map" {
                return coerce_value(parsed, depth + 1);
            }
        }
        if probe == "true" {
            return true;
        }
        if probe == "false" {
            return false;
        }
        return v;
    }
    if t == "map" {
        let out = #{};
        for k in v.keys() {
            out[k] = coerce_value(v[k], depth + 1);
        }
        return out;
    }
    if t == "array" {
        let out = [];
        for i in range(0, v.len()) {
            out.push(coerce_value(v[i], depth + 1));
        }
        return out;
    }
    v
}

// Apply one operator rule: strip removed params, drop out-of-whitelist enum
// values, then fill missing defaults (defaults run last so a value removed by
// the enum check can be backfilled).
fn apply_rules(args, rule) {
    let to_remove = rule["remove"];
    if type_of(to_remove) == "array" {
        for i in range(0, to_remove.len()) {
            args.remove(to_remove[i]);
        }
    }
    let enums = rule["enums"];
    if type_of(enums) == "map" {
        for k in enums.keys() {
            let allowed = enums[k];
            if type_of(allowed) == "array" && args.contains(k) && !allowed.contains(args[k]) {
                args.remove(k);
            }
        }
    }
    let defaults = rule["defaults"];
    if type_of(defaults) == "map" {
        for k in defaults.keys() {
            if !args.contains(k) || args[k] == () {
                args[k] = defaults[k];
            }
        }
    }
    args
}

fn transform(ctx) {
    if ctx.arguments == () {
        return ctx;
    }

    // Syntax must already be valid. If the arguments do not parse, either the
    // gateway healing_enabled setting (which repairs JSON syntax) is off or the
    // payload is unrecoverable — leave it untouched rather than guess.
    let parsed = parse_json(ctx.arguments);
    if type_of(parsed) != "map" {
        return ctx;
    }

    let coerced = coerce_value(parsed, 0);

    if type_of(ctx.tool_name) == "string" {
        let rules = repair_rules();
        let rule = rules[ctx.tool_name];
        if type_of(rule) == "map" {
            coerced = apply_rules(coerced, rule);
        }
    }

    // Compare both sides re-serialized through to_json so the diff is about
    // values, not object-key order or whitespace.
    if to_json(coerced) != to_json(parsed) {
        ctx.arguments = to_json(coerced);
        ctx.labels.push("tool_args_repaired");
    }

    ctx
}
