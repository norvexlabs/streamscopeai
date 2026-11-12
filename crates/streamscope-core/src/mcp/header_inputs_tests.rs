use std::collections::{BTreeMap, HashMap};

use proptest::prelude::*;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use super::*;
use crate::mcp::local_server::MAX_PACKAGES;

fn header(name: &str, input: Input) -> KeyValueInput {
    KeyValueInput { name: name.into(), input, variables: BTreeMap::new() }
}

fn stdio_package() -> serde_json::Value {
    serde_json::json!({"registryType": "npm", "identifier": "pkg", "version": "1.0.0", "transport": {"type": "stdio"}})
}

fn secret() -> Input {
    Input { is_required: true, is_secret: true, ..Input::default() }
}

fn required() -> Input {
    Input { is_required: true, ..Input::default() }
}

fn with_fillers(mut remote: Remote, fillers: &[(&str, Filler)]) -> Remote {
    remote.meta = Some(RemoteMeta {
        inputs: InputsMeta { fillers: fillers.iter().map(|(k, f)| ((*k).to_string(), *f)).collect() },
        ..RemoteMeta::default()
    });
    remote
}

/// The jicon remote: two URLs and two tokens.
fn jicon() -> Remote {
    Remote {
        kind: RemoteType::StreamableHttp,
        url: "https://jicon.example.com/mcp".into(),
        headers: vec![
            header("X-Jira-Url", required()),
            header("X-Jira-Token", secret()),
            header("X-Confluence-Url", required()),
            header("X-Confluence-Token", secret()),
        ],
        variables: BTreeMap::new(),
        meta: None,
    }
}

fn jicon_adopted() -> Remote {
    with_fillers(
        jicon(),
        &[
            ("X-Jira-Url", Filler::Admin),
            ("X-Confluence-Url", Filler::Admin),
            ("X-Jira-Token", Filler::User),
            ("X-Confluence-Token", Filler::User),
        ],
    )
}

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
}

fn header_value<'a>(auth: &'a UpstreamAuth, name: &str) -> Option<&'a str> {
    auth.headers().iter().find(|(n, _)| n.as_str().eq_ignore_ascii_case(name)).map(|(_, v)| v.to_str().unwrap())
}

#[test]
fn the_jicon_remote_resolves_admin_and_user_values_into_four_headers() {
    let admin = map(&[("X-Jira-Url", "https://jira.corp"), ("X-Confluence-Url", "https://wiki.corp")]);
    let user = map(&[("X-Jira-Token", "jira-pat-123456"), ("X-Confluence-Token", "conf-pat-654321")]);
    let auth = resolve(
        &jicon_adopted(),
        false,
        InputValues { admin: Some(&admin), user: Some(&user), client: None },
    )
    .expect("resolves");
    assert_eq!(auth.headers().len(), 4);
    assert_eq!(header_value(&auth, "x-jira-url"), Some("https://jira.corp"));
    assert_eq!(header_value(&auth, "x-confluence-token"), Some("conf-pat-654321"));
    assert!(auth.headers().iter().all(|(_, v)| v.is_sensitive()));
    let secrets: Vec<&str> = auth.secrets().collect();
    assert!(secrets.contains(&"jira-pat-123456") && secrets.contains(&"conf-pat-654321"));
    assert!(!secrets.contains(&"https://jira.corp"), "a non-secret value is not redacted");
    assert!(!format!("{auth:?}").contains("pat"), "Debug never prints a value");
}

#[test]
fn a_user_without_their_inputs_is_missing_exactly_those() {
    let admin = map(&[("X-Jira-Url", "https://jira.corp"), ("X-Confluence-Url", "https://wiki.corp")]);
    let user = map(&[("X-Jira-Token", "t")]);
    let err = resolve(&jicon_adopted(), false, InputValues { admin: Some(&admin), user: Some(&user), client: None })
        .unwrap_err();
    assert_eq!(
        err,
        ResolveError::Missing(Missing { admin: vec![], user: vec!["X-Confluence-Token".into()], client: vec![] })
    );
}

#[test]
fn a_user_value_for_an_admin_input_never_reaches_the_wire() {
    let admin = map(&[("X-Jira-Url", "https://jira.corp"), ("X-Confluence-Url", "https://wiki.corp")]);
    let user = map(&[
        ("X-Jira-Url", "https://evil.example"),
        ("X-Jira-Token", "a"),
        ("X-Confluence-Token", "b"),
        ("X-Undeclared", "c"),
    ]);
    let auth = resolve(&jicon_adopted(), false, InputValues { admin: Some(&admin), user: Some(&user), client: None })
        .unwrap();
    assert_eq!(header_value(&auth, "x-jira-url"), Some("https://jira.corp"));
    assert_eq!(header_value(&auth, "x-undeclared"), None);
}

#[test]
fn an_optional_input_with_no_value_omits_its_header() {
    let remote = with_fillers(
        Remote {
            url: "https://h.example/mcp".into(),
            headers: vec![header("X-Opt", Input::default()), header("X-Req", required())],
            ..Remote::default()
        },
        &[("X-Opt", Filler::User), ("X-Req", Filler::Admin)],
    );
    let admin = map(&[("X-Req", "v")]);
    let auth = resolve(&remote, false, InputValues { admin: Some(&admin), ..InputValues::default() }).unwrap();
    assert_eq!(auth.headers().len(), 1);
    assert_eq!(header_value(&auth, "x-opt"), None);
    // Positive control: with a value it is sent.
    let user = map(&[("X-Opt", "o")]);
    let auth = resolve(&remote, false, InputValues { admin: Some(&admin), user: Some(&user), client: None }).unwrap();
    assert_eq!(header_value(&auth, "x-opt"), Some("o"));
}

#[test]
fn a_default_fills_a_missing_value() {
    let remote = with_fillers(
        Remote {
            url: "https://h.example/mcp".into(),
            headers: vec![header("X-Region", Input { is_required: true, default: Some("eu".into()), ..Input::default() })],
            ..Remote::default()
        },
        &[("X-Region", Filler::User)],
    );
    assert!(required_user_input_ids(&validate_fillers(&remote, false).unwrap()).is_empty());
    let auth = resolve(&remote, false, InputValues::default()).unwrap();
    assert_eq!(header_value(&auth, "x-region"), Some("eu"));
}

#[test]
fn a_template_header_splices_its_variables() {
    let mut h = header("Authorization", Input { value: Some("Bearer {token}".into()), ..Input::default() });
    h.variables.insert("token".into(), secret());
    let remote = with_fillers(
        Remote { url: "https://h.example/mcp".into(), headers: vec![h], ..Remote::default() },
        &[("Authorization/token", Filler::Admin)],
    );
    let specs = validate_fillers(&remote, false).unwrap();
    assert_eq!(specs[0].declared.id, "Authorization/token");
    let admin = map(&[("Authorization/token", "s3cr3t-token")]);
    let auth = resolve(&remote, false, InputValues { admin: Some(&admin), ..InputValues::default() }).unwrap();
    assert_eq!(header_value(&auth, "authorization"), Some("Bearer s3cr3t-token"));
    let secrets: Vec<&str> = auth.secrets().collect();
    assert!(secrets.contains(&"s3cr3t-token") && secrets.contains(&"Bearer s3cr3t-token"));
    // On an OAuth upstream the token owns Authorization.
    assert_eq!(validate_fillers(&remote, true).unwrap_err(), RemoteError::ReservedForOauth);
}

#[test]
fn a_client_input_is_read_from_the_request_and_nothing_else_is() {
    let remote = with_fillers(
        Remote {
            url: "https://h.example/mcp".into(),
            headers: vec![header("X-Api-Token", secret())],
            ..Remote::default()
        },
        &[("X-Api-Token", Filler::Client)],
    );
    let specs = validate_fillers(&remote, false).unwrap();
    assert_eq!(client_header_names(&specs), vec!["x-api-token".to_string()]);
    let mut inbound = HeaderMap::new();
    inbound.insert(HeaderName::from_static("x-api-token"), HeaderValue::from_static("client-tok"));
    inbound.insert(HeaderName::from_static("x-other"), HeaderValue::from_static("no"));
    let auth = resolve(&remote, false, InputValues { client: Some(&inbound), ..InputValues::default() }).unwrap();
    assert_eq!(auth.headers().len(), 1);
    assert_eq!(header_value(&auth, "x-api-token"), Some("client-tok"));
    let err = resolve(&remote, false, InputValues::default()).unwrap_err();
    assert_eq!(
        err,
        ResolveError::Missing(Missing { admin: vec![], user: vec![], client: vec!["X-Api-Token".into()] })
    );
}

#[test]
fn reserved_headers_are_refused_and_their_neighbours_are_not() {
    for bad in [
        "Host", "content-type", "Content-Length", "Accept", "Accept-Encoding", "Origin", "Cookie",
        "User-Agent", "Last-Event-ID", "Mcp-Session-Id", "MCP-Protocol-Version", "Mcp-Method",
        "Mcp-Name", "Proxy-Authorization", "Sec-Fetch-Mode", "Forwarded", "X-Forwarded-For",
        "Via", "Expect", "Range", "Transfer-Encoding", "TE", "Trailer", "Upgrade", "Connection",
        "Keep-Alive", "X-Session-Id", "X-Tenant-Slug", "X-Auth-Request-Email",
    ] {
        assert!(is_reserved_header(bad), "{bad}");
        let remote = Remote { url: "https://h.example".into(), headers: vec![header(bad, required())], ..Remote::default() };
        assert_eq!(declared_inputs(&remote).unwrap_err(), RemoteError::ReservedHeader(bad.into()), "{bad}");
    }
    for ok in ["Authorization", "X-Api-Key", "X-Jira-Token", "Hostname", "X-Content", "X-Session", "Tenant"] {
        assert!(!is_reserved_header(ok), "{ok}");
    }
}

#[test]
fn declarations_that_cannot_be_honoured_are_refused() {
    let base = |headers| Remote { url: "https://h.example".into(), headers, ..Remote::default() };
    assert_eq!(
        declared_inputs(&base(vec![header("X-A", required()), header("x-a", required())])).unwrap_err(),
        RemoteError::DuplicateHeader("x-a".into())
    );
    assert_eq!(
        declared_inputs(&base(vec![header("X-A", Input { is_secret: true, default: Some("d".into()), ..Input::default() })]))
            .unwrap_err(),
        RemoteError::SecretWithDefault("X-A".into())
    );
    assert_eq!(
        declared_inputs(&base(vec![header("X-A", Input { is_secret: true, value: Some("fixed".into()), ..Input::default() })]))
            .unwrap_err(),
        RemoteError::SecretLiteral("X-A".into())
    );
    assert_eq!(
        declared_inputs(&base(vec![header("X-A", Input { format: InputFormat::Filepath, ..Input::default() })])).unwrap_err(),
        RemoteError::Filepath("X-A".into())
    );
    assert_eq!(
        declared_inputs(&base(vec![header("X A", required())])).unwrap_err(),
        RemoteError::InvalidHeaderName("X A".into())
    );
    // A fixed non-secret value is a header with no input.
    let fixed = base(vec![header("X-Version", Input { value: Some("2".into()), ..Input::default() })]);
    assert!(declared_inputs(&fixed).unwrap().is_empty());
    let auth = resolve(&fixed, false, InputValues::default()).unwrap();
    assert_eq!(header_value(&auth, "x-version"), Some("2"));
}

#[test]
fn fillers_must_cover_exactly_the_declared_inputs_and_agree_per_template() {
    assert_eq!(
        validate_fillers(&jicon(), false).unwrap_err(),
        RemoteError::MissingFiller("X-Jira-Url".into())
    );
    let mut extra = jicon_adopted();
    extra.meta.as_mut().unwrap().inputs.fillers.insert("X-Nope".into(), Filler::Admin);
    assert_eq!(validate_fillers(&extra, false).unwrap_err(), RemoteError::UnknownFiller("X-Nope".into()));

    let mut h = header("X-Auth", Input { value: Some("{user}:{pass}".into()), ..Input::default() });
    h.variables.insert("user".into(), required());
    h.variables.insert("pass".into(), secret());
    let remote = Remote { url: "https://h.example".into(), headers: vec![h], ..Remote::default() };
    let mixed = with_fillers(remote.clone(), &[("X-Auth/user", Filler::Admin), ("X-Auth/pass", Filler::User)]);
    assert_eq!(validate_fillers(&mixed, false).unwrap_err(), RemoteError::MixedFillers("X-Auth".into()));
    let client = with_fillers(remote.clone(), &[("X-Auth/user", Filler::Client), ("X-Auth/pass", Filler::Client)]);
    assert_eq!(validate_fillers(&client, false).unwrap_err(), RemoteError::ClientTemplate("X-Auth/user".into()));
    let same = with_fillers(remote, &[("X-Auth/user", Filler::User), ("X-Auth/pass", Filler::User)]);
    let specs = validate_fillers(&same, false).unwrap();
    assert_eq!(required_user_input_ids(&specs), vec!["X-Auth/user".to_string(), "X-Auth/pass".to_string()]);
}

#[test]
fn two_upstreams_claiming_one_client_header_collide() {
    let a = with_fillers(
        Remote { url: "https://a.example".into(), headers: vec![header("X-Token", secret())], ..Remote::default() },
        &[("X-Token", Filler::Client)],
    );
    let b = with_fillers(
        Remote { url: "https://b.example".into(), headers: vec![header("x-token", secret())], ..Remote::default() },
        &[("x-token", Filler::Client)],
    );
    let c = with_fillers(
        Remote { url: "https://c.example".into(), headers: vec![header("x-token", secret())], ..Remote::default() },
        &[("x-token", Filler::User)],
    );
    let (a, b, c) = (
        validate_fillers(&a, false).unwrap(),
        validate_fillers(&b, false).unwrap(),
        validate_fillers(&c, false).unwrap(),
    );
    assert_eq!(client_header_collision(&a, &b), Some("x-token".into()));
    assert_eq!(client_header_collision(&a, &c), None, "a user-filled header is not the client's");
}

#[test]
fn values_are_checked_against_their_declaration() {
    let num = Input { format: InputFormat::Number, ..Input::default() };
    assert!(validate_value("n", &num, "42.5").is_ok());
    assert!(validate_value("n", &num, "4x").is_err());
    assert!(validate_value("n", &num, "NaN").is_err());
    let b = Input { format: InputFormat::Boolean, ..Input::default() };
    assert!(validate_value("b", &b, "true").is_ok());
    assert!(validate_value("b", &b, "yes").is_err());
    let ch = Input { choices: vec!["eu".into(), "us".into()], ..Input::default() };
    assert!(validate_value("c", &ch, "us").is_ok());
    assert!(validate_value("c", &ch, "ap").is_err());
    let s = Input::default();
    for bad in ["", " lead", "trail ", "a\r\nX-Evil: 1", "nul\0", "del\x7f"] {
        assert!(validate_value("s", &s, bad).is_err(), "{bad:?}");
    }
    assert!(validate_value("s", &s, "in side\tok").is_ok());
    assert!(validate_value("s", &s, &"a".repeat(MAX_INPUT_VALUE_BYTES)).is_ok());
    assert!(validate_value("s", &s, &"a".repeat(MAX_INPUT_VALUE_BYTES + 1)).is_err());
}

#[test]
fn a_url_is_finished_from_its_variables() {
    let mut remote = Remote { url: "https://{tenant}.example.com/mcp".into(), ..Remote::default() };
    remote.variables.insert("tenant".into(), required());
    assert_eq!(finish_url(&remote, &map(&[("tenant", "acme")])).unwrap(), "https://acme.example.com/mcp");
    assert_eq!(finish_url(&remote, &HashMap::new()).unwrap_err(), RemoteError::MissingUrlVariable("tenant".into()));
    assert_eq!(
        finish_url(&remote, &map(&[("tenant", "acme"), ("x", "y")])).unwrap_err(),
        RemoteError::UnknownUrlVariable("x".into())
    );
    remote.variables.insert("tenant".into(), Input { default: Some("demo".into()), ..Input::default() });
    assert_eq!(finish_url(&remote, &HashMap::new()).unwrap(), "https://demo.example.com/mcp");
    remote.variables.insert("tenant".into(), secret());
    assert_eq!(
        finish_url(&remote, &map(&[("tenant", "acme")])).unwrap_err(),
        RemoteError::SecretUrlVariable("tenant".into())
    );
    let plain = Remote { url: "ftp://h.example".into(), ..Remote::default() };
    assert_eq!(finish_url(&plain, &HashMap::new()).unwrap_err(), RemoteError::InvalidUrl);
}

fn jicon_server() -> ServerJson {
    ServerJson {
        schema: Some(SERVER_JSON_SCHEMA.into()),
        name: "io.github.example/jicon".into(),
        description: "Jira, Confluence and Tempo".into(),
        version: "1.0.0".into(),
        remotes: vec![jicon()],
        ..ServerJson::default()
    }
}

#[test]
fn a_server_json_round_trips_and_validates() {
    let mut s = jicon_server();
    s.set_catalog_meta(&CatalogMeta { category: Some("Dev".into()), featured: true, ..CatalogMeta::default() });
    s.meta.insert("io.example/other".into(), serde_json::json!({"k": 1}));
    s.validate().unwrap();
    let wire = serde_json::to_value(&s).unwrap();
    assert_eq!(wire["remotes"][0]["type"], "streamable-http");
    assert_eq!(wire["remotes"][0]["headers"][1]["isSecret"], true);
    assert_eq!(wire["_meta"][CATALOG_META_KEY]["category"], "Dev");
    let back: ServerJson = serde_json::from_value(wire).unwrap();
    assert_eq!(back, s);
    assert_eq!(back.catalog_meta().category.as_deref(), Some("Dev"));
}

#[test]
fn a_server_json_outside_the_schema_is_refused() {
    let ok = jicon_server();
    for (mutate, want) in [
        (Box::new(|s: &mut ServerJson| s.name = "noslash".into()) as Box<dyn Fn(&mut ServerJson)>, RemoteError::InvalidServerName),
        (Box::new(|s: &mut ServerJson| s.name = "a/b/c".into()), RemoteError::InvalidServerName),
        (Box::new(|s: &mut ServerJson| s.description = String::new()), RemoteError::InvalidDescription),
        (Box::new(|s: &mut ServerJson| s.description = "d".repeat(101)), RemoteError::InvalidDescription),
        (Box::new(|s: &mut ServerJson| s.version = "^1.0.0".into()), RemoteError::InvalidVersion),
        (Box::new(|s: &mut ServerJson| s.remotes.clear()), RemoteError::NoTransport),
        (
            Box::new(|s: &mut ServerJson| {
                s.remotes.clear();
                s.packages = Some(serde_json::json!([]));
            }),
            RemoteError::NoTransport,
        ),
        (
            Box::new(|s: &mut ServerJson| {
                s.remotes.clear();
                s.packages = Some(serde_json::json!({"registryType": "npm"}));
            }),
            RemoteError::InvalidPackages,
        ),
        (
            Box::new(|s: &mut ServerJson| {
                s.remotes.clear();
                s.packages = Some(serde_json::Value::Array(vec![stdio_package(); MAX_PACKAGES + 1]));
            }),
            RemoteError::InvalidPackages,
        ),
        (
            Box::new(|s: &mut ServerJson| {
                s.remotes.clear();
                s.packages = Some(serde_json::json!([stdio_package(), {"registryType": "npm", "identifier": "x"}]));
            }),
            RemoteError::InvalidPackage(1),
        ),
        (Box::new(|s: &mut ServerJson| s.remotes[0].url = "mcp.example".into()), RemoteError::InvalidUrl),
        (
            Box::new(|s: &mut ServerJson| {
                s.meta.insert(CATALOG_META_KEY.into(), serde_json::json!({"featured": "yes"}));
            }),
            RemoteError::InvalidCatalogMeta,
        ),
    ] {
        let mut s = ok.clone();
        mutate(&mut s);
        assert_eq!(s.validate().unwrap_err(), want);
    }
    let mut boundary = ok.clone();
    boundary.description = "d".repeat(100);
    boundary.validate().unwrap();

    // A package stands in for a remote: a document with no remote and one
    // package is a server a developer's machine starts. The list is accepted
    // up to its cap, beside a remote or alone.
    let mut local = ok.clone();
    local.remotes.clear();
    local.packages = Some(serde_json::json!([stdio_package()]));
    local.validate().unwrap();
    local.packages = Some(serde_json::Value::Array(vec![stdio_package(); MAX_PACKAGES]));
    local.validate().unwrap();
    // Beside a remote, `packages` is kept verbatim and never read: the same
    // values refused above save as they are.
    for packages in [
        serde_json::json!({"registryType": "npm"}),
        serde_json::json!([stdio_package(), {"registryType": "npm", "identifier": "x"}]),
        serde_json::Value::Array(vec![stdio_package(); MAX_PACKAGES + 1]),
        serde_json::json!([]),
    ] {
        let mut both = ok.clone();
        both.packages = Some(packages.clone());
        both.validate().unwrap();
        assert_eq!(serde_json::to_value(&both).unwrap()["packages"], packages);
    }
}

#[test]
fn an_unmatched_identifier_stays_literal() {
    let vars: HashMap<&str, &str> = [("a", "1")].into_iter().collect();
    assert_eq!(splice("{a}-{b}-{{a}}-{", &vars), "1-{b}-{1}-{");
}

proptest! {
    /// A substituted value is never scanned again: whatever braces it holds,
    /// the output is the template with each known `{name}` replaced by its
    /// value verbatim.
    #[test]
    fn a_value_is_never_expanded_again(
        prefix in "[a-z ]{0,6}",
        suffix in "[a-z ]{0,6}",
        value in "[{}ab]{0,12}",
    ) {
        let vars: HashMap<&str, &str> = [("a", value.as_str()), ("b", "B")].into_iter().collect();
        let template = format!("{prefix}{{a}}{suffix}");
        prop_assert_eq!(splice(&template, &vars), format!("{prefix}{value}{suffix}"));
    }

    /// No value, wherever it comes from, adds a header or a line: resolution
    /// either refuses it or sends exactly the declared headers, each a valid
    /// field-value.
    #[test]
    fn a_value_never_creates_a_header_boundary(
        value in proptest::collection::vec(any::<u8>(), 1..24),
        templated in any::<bool>(),
    ) {
        let value = String::from_utf8_lossy(&value).into_owned();
        let mut h = header("X-Token", secret());
        let id = if templated {
            h.input = Input { value: Some("Token {t}".into()), ..Input::default() };
            h.variables.insert("t".into(), secret());
            "X-Token/t"
        } else {
            "X-Token"
        };
        let remote = with_fillers(
            Remote { url: "https://h.example".into(), headers: vec![h], ..Remote::default() },
            &[(id, Filler::User)],
        );
        let user = map(&[(id, value.as_str())]);
        let resolved = resolve(&remote, false, InputValues { user: Some(&user), ..InputValues::default() });
        // Positive control: a plain visible-ASCII value always resolves, so
        // the property below is exercised, not vacuously skipped.
        if value.bytes().all(|b| b.is_ascii_alphanumeric()) {
            prop_assert!(resolved.is_ok(), "{value:?}");
        }
        if let Ok(auth) = resolved {
            prop_assert_eq!(auth.headers().len(), 1);
            let bytes = auth.headers()[0].1.as_bytes();
            prop_assert!(!bytes.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)));
        }
    }

    /// Each input is read only from its own filler's source: with a distinct
    /// value under every id in every source, each header carries the value of
    /// its filler's source alone.
    #[test]
    fn an_input_is_read_only_from_its_own_filler(fillers in proptest::collection::vec(0u8..3, 4)) {
        let names = ["X-A", "X-B", "X-C", "X-D"];
        let to_filler = |f: u8| match f { 0 => Filler::Admin, 1 => Filler::User, _ => Filler::Client };
        let pairs: Vec<(&str, Filler)> = names.iter().zip(&fillers).map(|(n, f)| (*n, to_filler(*f))).collect();
        let remote = with_fillers(
            Remote {
                url: "https://h.example".into(),
                headers: names.iter().map(|n| header(n, required())).collect(),
                ..Remote::default()
            },
            &pairs,
        );
        let admin: HashMap<String, String> = names.iter().map(|n| ((*n).to_string(), format!("admin-{n}"))).collect();
        let user: HashMap<String, String> = names.iter().map(|n| ((*n).to_string(), format!("user-{n}"))).collect();
        let mut client = HeaderMap::new();
        for n in names {
            client.insert(HeaderName::from_bytes(n.as_bytes()).unwrap(), HeaderValue::from_str(&format!("client-{n}")).unwrap());
        }
        let auth = resolve(&remote, false, InputValues { admin: Some(&admin), user: Some(&user), client: Some(&client) }).unwrap();
        for (n, f) in pairs {
            let want = match f { Filler::Admin => "admin", Filler::User => "user", Filler::Client => "client" };
            let expected = format!("{want}-{n}");
            prop_assert_eq!(header_value(&auth, n), Some(expected.as_str()));
        }
    }
}

#[test]
fn a_stored_value_the_declaration_no_longer_allows_reads_as_unfilled() {
    let mut region = required();
    region.choices = vec!["eu".into()];
    let remote = with_fillers(
        Remote { url: "https://h.example".into(), headers: vec![header("X-Region", region)], ..Remote::default() },
        &[("X-Region", Filler::User)],
    );
    let stale = map(&[("X-Region", "us")]);
    assert_eq!(
        resolve(&remote, false, InputValues { user: Some(&stale), ..InputValues::default() }).unwrap_err(),
        ResolveError::Missing(Missing { admin: vec![], user: vec!["X-Region".into()], client: vec![] })
    );
    // Positive control: a value the choices allow is sent.
    let ok = map(&[("X-Region", "eu")]);
    let auth = resolve(&remote, false, InputValues { user: Some(&ok), ..InputValues::default() }).unwrap();
    assert_eq!(header_value(&auth, "x-region"), Some("eu"));
}

#[test]
fn each_cap_holds_at_its_boundary() {
    assert_eq!(MAX_INPUT_VALUE_BYTES, 8 * 1024);
    let base = |headers| Remote { url: "https://h.example".into(), headers, ..Remote::default() };
    let many = |n: usize| (0..n).map(|i| header(&format!("X-H{i}"), Input::default())).collect::<Vec<_>>();
    assert!(declared_inputs(&base(many(MAX_HEADERS))).is_ok());
    assert_eq!(declared_inputs(&base(many(MAX_HEADERS + 1))).unwrap_err(), RemoteError::TooManyHeaders);

    let named = |len: usize| base(vec![header(&format!("X{}", "a".repeat(len - 1)), Input::default())]);
    assert!(declared_inputs(&named(128)).is_ok());
    assert!(matches!(declared_inputs(&named(129)).unwrap_err(), RemoteError::InvalidHeaderName(_)));

    let templated = |n: usize| {
        let mut h = header("X-T", Input { value: Some("{v0}".into()), ..Input::default() });
        h.variables = (0..n).map(|i| (format!("v{i}"), Input::default())).collect();
        base(vec![h])
    };
    assert!(declared_inputs(&templated(MAX_VARIABLES)).is_ok());
    assert_eq!(declared_inputs(&templated(MAX_VARIABLES + 1)).unwrap_err(), RemoteError::TooManyVariables("X-T".into()));

    let url_vars = |n: usize| Remote {
        url: "https://h.example".into(),
        variables: (0..n).map(|i| (format!("v{i}"), Input::default())).collect(),
        ..Remote::default()
    };
    assert!(finish_url(&url_vars(MAX_VARIABLES), &HashMap::new()).is_ok());
    assert_eq!(finish_url(&url_vars(MAX_VARIABLES + 1), &HashMap::new()).unwrap_err(), RemoteError::TooManyVariables("url".into()));
}

#[test]
fn a_url_template_must_be_a_whole_http_url() {
    let with = |url: &str| Remote { url: url.into(), ..Remote::default() };
    for ok in ["https://h", "http://h", "https://h.example/mcp?x=1"] {
        assert!(finish_url(&with(ok), &HashMap::new()).is_ok(), "{ok}");
    }
    for bad in ["http://", "https://", "https:///p", "https://?q", "ftp://h", "h.example", "https://h ex", "https://h\tx", ""] {
        assert_eq!(finish_url(&with(bad), &HashMap::new()).unwrap_err(), RemoteError::InvalidUrl, "{bad:?}");
    }
    // A variable the URL never names needs no value.
    let mut r = with("https://h.example");
    r.variables.insert("unused".into(), Input::default());
    assert_eq!(finish_url(&r, &HashMap::new()).unwrap(), "https://h.example");
}

#[test]
fn a_server_name_is_reverse_dns_with_one_slash_and_a_bounded_length() {
    for ok in ["a/b", "io.github.user/weather", "a-b.c/d_e.f-g", &format!("a/{}", "b".repeat(198))] {
        assert!(is_valid_server_name(ok), "{ok}");
    }
    for bad in ["ab", "/ab", "ab/", "a/b/c", "a_b/c", "a/b c", "a b/c", &format!("a/{}", "b".repeat(199))] {
        assert!(!is_valid_server_name(bad), "{bad}");
    }
    let mut s = jicon_server();
    s.title = Some(String::new());
    assert_eq!(s.validate().unwrap_err(), RemoteError::InvalidTitle);
    s.title = Some("t".repeat(101));
    assert_eq!(s.validate().unwrap_err(), RemoteError::InvalidTitle);
    s.title = Some("t".repeat(100));
    s.validate().unwrap();
    assert_eq!(s.display_name(), "t".repeat(100));
    s.title = None;
    assert_eq!(s.display_name(), "io.github.example/jicon");
}

#[test]
fn a_variable_used_twice_is_one_input() {
    let mut h = header("X-Pair", Input { value: Some("{t}:{t}".into()), ..Input::default() });
    h.variables.insert("t".into(), required());
    let remote = Remote { url: "https://h.example".into(), headers: vec![h], ..Remote::default() };
    let ids: Vec<String> = declared_inputs(&remote).unwrap().into_iter().map(|d| d.id).collect();
    assert_eq!(ids, vec!["X-Pair/t".to_string()]);
    let remote = with_fillers(remote, &[("X-Pair/t", Filler::Admin)]);
    let admin = map(&[("X-Pair/t", "v")]);
    let auth = resolve(&remote, false, InputValues { admin: Some(&admin), ..InputValues::default() }).unwrap();
    assert_eq!(header_value(&auth, "x-pair"), Some("v:v"));
}

#[test]
fn defaults_are_left_out_of_the_document_and_set_fields_are_kept() {
    assert_eq!(serde_json::to_value(Input::default()).unwrap(), serde_json::json!({}));
    let set = Input { is_required: true, is_secret: true, format: InputFormat::Number, ..Input::default() };
    assert_eq!(
        serde_json::to_value(&set).unwrap(),
        serde_json::json!({"isRequired": true, "isSecret": true, "format": "number"})
    );
    assert_eq!(RemoteType::StreamableHttp.transport_str(), "streamable_http");
    assert_eq!(RemoteType::Sse.transport_str(), "sse");
    assert_eq!(jicon_adopted().filler("X-Jira-Token"), Some(Filler::User));
    assert_eq!(jicon().filler("X-Jira-Token"), None);
    let mut s = jicon_server();
    s.set_catalog_meta(&CatalogMeta { featured: true, ..CatalogMeta::default() });
    assert!(s.meta.contains_key(CATALOG_META_KEY));
    s.set_catalog_meta(&CatalogMeta::default());
    assert!(!s.meta.contains_key(CATALOG_META_KEY), "an empty meta is removed");
    assert_eq!(RemoteError::InvalidTitle.to_string(), "title must be 1-100 characters");
}

#[test]
fn an_upstream_auth_holds_exactly_what_was_pushed() {
    assert!(UpstreamAuth::none().is_empty());
    assert!(UpstreamAuth::none().secrets().next().is_none());
    let auth = UpstreamAuth::bearer("tok-12345678").expect("a valid token");
    assert!(!auth.is_empty());
    assert_eq!(header_value(&auth, "authorization"), Some("Bearer tok-12345678"));
    assert_eq!(auth.secrets().collect::<Vec<_>>(), vec!["tok-12345678"]);
    assert!(UpstreamAuth::bearer("bad\ntoken").is_none());
    let mut other = UpstreamAuth::none();
    assert_eq!(other.push_bearer("x\r\ny"), None);
    assert!(other.is_empty());
    assert_eq!(other.push_bearer("ok"), Some(()));
    let debug = format!("{auth:?}");
    assert!(debug.contains("authorization"), "{debug}");
    assert!(!debug.contains("tok-12345678"), "{debug}");
}

#[test]
fn a_template_mixing_required_and_optional_variables_is_refused() {
    let mut h = header("X-Auth", Input { value: Some("{key}:{tenant}".into()), ..Input::default() });
    h.variables.insert("key".into(), required());
    h.variables.insert("tenant".into(), Input::default());
    let remote = Remote { url: "https://h.example".into(), headers: vec![h.clone()], ..Remote::default() };
    assert_eq!(declared_inputs(&remote).unwrap_err(), RemoteError::MixedRequired("X-Auth".into()));
    // Positive controls: the header itself required, or every variable alike.
    let mut whole = h.clone();
    whole.input.is_required = true;
    assert!(declared_inputs(&Remote { headers: vec![whole], ..remote.clone() }).is_ok());
    let mut alike = h;
    alike.variables.insert("tenant".into(), required());
    assert!(declared_inputs(&Remote { headers: vec![alike], ..remote }).is_ok());
}

#[test]
fn an_invalid_given_value_is_missing_and_never_replaced_by_the_default() {
    let mut region = Input { choices: vec!["eu".into(), "us".into()], default: Some("eu".into()), ..Input::default() };
    region.is_required = false;
    let remote = with_fillers(
        Remote { url: "https://h.example".into(), headers: vec![header("X-Region", region)], ..Remote::default() },
        &[("X-Region", Filler::Client)],
    );
    let mut sent = HeaderMap::new();
    sent.insert(HeaderName::from_static("x-region"), HeaderValue::from_static("apac"));
    assert_eq!(
        resolve(&remote, false, InputValues { client: Some(&sent), ..InputValues::default() }).unwrap_err(),
        ResolveError::Missing(Missing { admin: vec![], user: vec![], client: vec!["X-Region".into()] })
    );
    // A value no `&str` holds (obs-text) is given too: missing, not the default.
    let mut obs = HeaderMap::new();
    obs.insert(HeaderName::from_static("x-region"), HeaderValue::from_bytes(b"z\xfcrich").unwrap());
    assert!(matches!(
        resolve(&remote, false, InputValues { client: Some(&obs), ..InputValues::default() }),
        Err(ResolveError::Missing(_))
    ));
    // Positive controls: an absent value takes the default; a valid one is sent.
    let auth = resolve(&remote, false, InputValues::default()).unwrap();
    assert_eq!(header_value(&auth, "x-region"), Some("eu"));
    sent.insert(HeaderName::from_static("x-region"), HeaderValue::from_static("us"));
    let auth = resolve(&remote, false, InputValues { client: Some(&sent), ..InputValues::default() }).unwrap();
    assert_eq!(header_value(&auth, "x-region"), Some("us"));
}

#[test]
fn a_url_variable_cannot_move_the_request_to_another_server() {
    let mut remote = Remote { url: "https://{site}.atlassian.net/mcp".into(), ..Remote::default() };
    remote.variables.insert("site".into(), required());
    for bad in ["evil.example/x?", "evil.example#", "u@evil.example", "a b", "a\\b"] {
        assert!(
            matches!(finish_url(&remote, &map(&[("site", bad)])), Err(RemoteError::InvalidValue { .. })),
            "{bad}"
        );
    }
    assert_eq!(
        finish_url(&remote, &map(&[("site", "acme-corp.eu")])).unwrap(),
        "https://acme-corp.eu.atlassian.net/mcp"
    );
    // A port is a plain value: alone it cannot name another host.
    let mut hostport = Remote { url: "http://{host}/mcp".into(), ..Remote::default() };
    hostport.variables.insert("host".into(), required());
    assert_eq!(finish_url(&hostport, &map(&[("host", "mock:3333")])).unwrap(), "http://mock:3333/mcp");
}

#[test]
fn a_client_input_is_refused_on_an_sse_remote() {
    let sse = |filler| {
        with_fillers(
            Remote { kind: RemoteType::Sse, url: "https://h.example/sse".into(), headers: vec![header("X-Token", secret())], ..Remote::default() },
            &[("X-Token", filler)],
        )
    };
    assert_eq!(validate_fillers(&sse(Filler::Client), false).unwrap_err(), RemoteError::ClientOnSse("X-Token".into()));
    // Positive control: another filler on SSE, or a client one on streamable-http.
    assert!(validate_fillers(&sse(Filler::User), false).is_ok());
    let mut http = sse(Filler::Client);
    http.kind = RemoteType::StreamableHttp;
    assert!(validate_fillers(&http, false).is_ok());
}

#[test]
fn a_client_value_is_redacted_even_when_not_declared_secret() {
    let remote = with_fillers(
        Remote { url: "https://h.example".into(), headers: vec![header("X-Token", required())], ..Remote::default() },
        &[("X-Token", Filler::Client)],
    );
    let mut sent = HeaderMap::new();
    sent.insert(HeaderName::from_static("x-token"), HeaderValue::from_static("client-cred-1"));
    let auth = resolve(&remote, false, InputValues { client: Some(&sent), ..InputValues::default() }).unwrap();
    assert!(auth.secrets().any(|s| s == "client-cred-1"));
    // A short flag is not treated as a credential.
    sent.insert(HeaderName::from_static("x-token"), HeaderValue::from_static("true"));
    let auth = resolve(&remote, false, InputValues { client: Some(&sent), ..InputValues::default() }).unwrap();
    assert_eq!(auth.secrets().count(), 0);
    // A client value past the stored-value cap (a large JWT) is still sent.
    let big = "j".repeat(MAX_INPUT_VALUE_BYTES + 100);
    sent.insert(HeaderName::from_static("x-token"), HeaderValue::from_str(&big).unwrap());
    let auth = resolve(&remote, false, InputValues { client: Some(&sent), ..InputValues::default() }).unwrap();
    assert_eq!(header_value(&auth, "x-token").map(str::len), Some(big.len()));
    // Positive control: a non-secret admin value is not redacted.
    let admin_remote = with_fillers(
        Remote { url: "https://h.example".into(), headers: vec![header("X-Region", required())], ..Remote::default() },
        &[("X-Region", Filler::Admin)],
    );
    let admin = map(&[("X-Region", "eu")]);
    let auth = resolve(&admin_remote, false, InputValues { admin: Some(&admin), ..InputValues::default() }).unwrap();
    assert_eq!(auth.secrets().count(), 0);
}

#[test]
fn a_variable_of_a_secret_header_cannot_carry_a_default() {
    let mut h = header("Authorization", Input { is_secret: true, value: Some("Bearer {token}".into()), ..Input::default() });
    h.variables.insert("token".into(), Input { default: Some("sk-live-123".into()), ..Input::default() });
    let remote = Remote { url: "https://h.example".into(), headers: vec![h.clone()], ..Remote::default() };
    assert_eq!(declared_inputs(&remote).unwrap_err(), RemoteError::SecretWithDefault("Authorization/token".into()));
    // Positive control: without the default it is accepted.
    h.variables.insert("token".into(), required());
    assert!(declared_inputs(&Remote { headers: vec![h], ..remote }).is_ok());
}

#[test]
fn a_template_whose_own_text_cannot_be_a_header_value_is_refused() {
    for bad in ["{token} ", " {token}", "a\u{7}{token}"] {
        let mut h = header("X-Key", Input { value: Some(bad.into()), ..Input::default() });
        h.variables.insert("token".into(), required());
        let remote = Remote { url: "https://h.example".into(), headers: vec![h], ..Remote::default() };
        assert_eq!(declared_inputs(&remote).unwrap_err(), RemoteError::InvalidLiteral("X-Key".into()), "{bad:?}");
    }
    let mut ok = header("X-Key", Input { value: Some("Token {token}".into()), ..Input::default() });
    ok.variables.insert("token".into(), required());
    assert!(declared_inputs(&Remote { url: "https://h.example".into(), headers: vec![ok], ..Remote::default() }).is_ok());
}

#[test]
fn the_inputs_of_a_template_are_exactly_the_names_splice_fills() {
    // `{x{b}` with names `x{b` and `b`: splice fills `x{b` and never reaches
    // `b`, so `b` is not an input of the header.
    let mut h = header("X-T", Input { value: Some("{x{b}".into()), ..Input::default() });
    h.variables.insert("x{b".into(), required());
    h.variables.insert("b".into(), required());
    let remote = Remote { url: "https://h.example".into(), headers: vec![h], ..Remote::default() };
    let ids: Vec<String> = declared_inputs(&remote).unwrap().into_iter().map(|d| d.id).collect();
    assert_eq!(ids, vec!["X-T/x{b".to_string()]);
}

#[test]
fn a_default_must_be_a_value_the_input_accepts() {
    let base = |input: Input| Remote { url: "https://h.example".into(), headers: vec![header("X-Region", input)], ..Remote::default() };
    for bad in [
        Input { default: Some(String::new()), ..Input::default() },
        Input { default: Some(" eu".into()), ..Input::default() },
        Input { default: Some("ap".into()), choices: vec!["eu".into(), "us".into()], ..Input::default() },
        Input { default: Some("many".into()), format: InputFormat::Number, ..Input::default() },
    ] {
        assert!(matches!(declared_inputs(&base(bad.clone())), Err(RemoteError::InvalidValue { .. })), "{bad:?}");
    }
    assert!(declared_inputs(&base(Input { default: Some("eu".into()), choices: vec!["eu".into()], ..Input::default() })).is_ok());
}

#[test]
fn a_url_naming_an_undeclared_variable_is_refused() {
    let remote = Remote { url: "https://api.example.com/{workspace}/mcp".into(), ..Remote::default() };
    assert_eq!(finish_url(&remote, &HashMap::new()).unwrap_err(), RemoteError::MissingUrlVariable("workspace".into()));
    let mut declared = remote.clone();
    declared.variables.insert("workspace".into(), required());
    assert_eq!(
        finish_url(&declared, &map(&[("workspace", "w1")])).unwrap(),
        "https://api.example.com/w1/mcp"
    );
}

#[test]
fn a_url_variable_default_is_checked_like_a_value() {
    let mut remote = Remote { url: "https://{site}.example.com/mcp".into(), ..Remote::default() };
    remote.variables.insert("site".into(), Input { default: Some("acme/eu".into()), ..Input::default() });
    let doc = ServerJson { remotes: vec![remote.clone()], ..jicon_server() };
    assert!(matches!(doc.validate(), Err(RemoteError::InvalidValue { .. })));
    remote.variables.insert("site".into(), Input { default: Some("acme".into()), ..Input::default() });
    assert!(ServerJson { remotes: vec![remote], ..jicon_server() }.validate().is_ok());
}

#[test]
fn a_version_is_never_a_range_or_latest() {
    for ok in ["1.0.0", "2.1.0-alpha", "2025.11.1", "v3"] {
        assert!(is_valid_version(ok), "{ok}");
    }
    for bad in ["^1.0", "~1", ">=1", "1.x", "1.2.X", "1.*", "*", "latest", "1 || 2", "1 - 2", ""] {
        assert!(!is_valid_version(bad), "{bad}");
    }
}

/// A remote's `_meta` namespaces other than the gateway's survive a parse and
/// a serialization unchanged, beside the gateway's own fillers.
#[test]
fn a_remotes_foreign_meta_round_trips() {
    let wire = serde_json::json!({
        "type": "streamable-http",
        "url": "https://mcp.example/mcp",
        "_meta": {
            "io.example/vendor": {"tier": "gold", "n": [1, 2]},
            "ai.streamscope/inputs": {"fillers": {"X-Key": "admin"}}
        }
    });
    let remote: Remote = serde_json::from_value(wire.clone()).unwrap();
    let meta = remote.meta.as_ref().unwrap();
    assert_eq!(meta.inputs.fillers.get("X-Key"), Some(&Filler::Admin));
    assert_eq!(meta.other.get("io.example/vendor"), Some(&wire["_meta"]["io.example/vendor"]));
    assert!(!meta.other.contains_key("ai.streamscope/inputs"), "the gateway's namespace is typed, not kept twice");
    assert_eq!(serde_json::to_value(&remote).unwrap(), wire);
}

/// A remote whose `_meta` never carried the gateway's namespace reads back
/// without it: no filler, no namespace written.
#[test]
fn a_remote_without_fillers_round_trips_without_the_gateways_namespace() {
    let wire = serde_json::json!({
        "type": "streamable-http",
        "url": "https://mcp.example/mcp",
        "_meta": { "io.example/vendor": {"tier": "gold"} }
    });
    let remote: Remote = serde_json::from_value(wire.clone()).unwrap();
    assert!(remote.meta.as_ref().unwrap().inputs.is_empty());
    assert_eq!(serde_json::to_value(&remote).unwrap(), wire);
}
