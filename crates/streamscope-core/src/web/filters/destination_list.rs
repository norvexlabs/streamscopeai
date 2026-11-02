//! The tenant's destination lists attached to the Web tool, as a URL filter.
//!
//! A URL's host and port (the scheme's default when absent) are matched
//! against the lists' entries (`streamscope_client_templates::destination`): a host
//! name against name and `*.suffix` entries, an IP-literal host against
//! address and prefix entries. The filter runs before any resolution, so a
//! prefix entry never matches a name.
//!
//! - Nothing attached as allow → every host not blocked passes.
//! - A list attached as allow → only hosts it matches pass; an attached allow
//!   list with no entries (or none readable) passes nothing.
//! - A block match never passes, whatever an allow says. A blocked entry
//!   without ports blocks every port of its host.

use std::pin::Pin;

use url::Url;

use streamscope_client_templates::destination::Mode;

use crate::web::settings::WebDestinations;
use crate::web::url_filter::{FilterContext, FilterError, FilterVerdict, UrlFilter};

#[derive(Debug, Clone, Default)]
pub struct DestinationListFilter {
    lists: WebDestinations,
}

impl DestinationListFilter {
    pub fn new(lists: WebDestinations) -> Self {
        Self { lists }
    }

    /// `true` when no list is attached (the filter is a no-op).
    pub fn is_inert(&self) -> bool {
        !self.lists.allow_attached && self.lists.block.is_empty() && !self.lists.unreadable_block
    }
}

impl UrlFilter for DestinationListFilter {
    fn id(&self) -> &'static str {
        "destination_list"
    }

    fn evaluate<'a>(
        &'a self,
        url: &'a Url,
        _ctx: &'a FilterContext,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<FilterVerdict, FilterError>> + Send + 'a>>
    {
        Box::pin(async move {
            let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
                return Ok(FilterVerdict::Deny { reason: "url has no host".into() });
            };
            if self.lists.unreadable_block {
                return Ok(FilterVerdict::Deny { reason: "a blocked destination list could not be read".into() });
            }
            if self.lists.block.matches(host, port, Mode::Block) {
                return Ok(FilterVerdict::Deny { reason: format!("`{host}:{port}` is on a blocked destination list") });
            }
            if self.lists.allow_attached && !self.lists.allow.matches(host, port, Mode::Allow) {
                return Ok(FilterVerdict::Deny { reason: format!("`{host}:{port}` is on no allowed destination list") });
            }
            Ok(FilterVerdict::Allow)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use streamscope_client_templates::destination::DestinationSet;

    fn filter(allow: &[&str], block: &[&str]) -> DestinationListFilter {
        DestinationListFilter::new(WebDestinations {
            allow: DestinationSet::parse(allow).unwrap(),
            allow_attached: !allow.is_empty(),
            block: DestinationSet::parse(block).unwrap(),
            unreadable_block: false,
        })
    }

    async fn verdict(f: &DestinationListFilter, u: &str) -> FilterVerdict {
        f.evaluate(&Url::parse(u).unwrap(), &FilterContext::default()).await.unwrap()
    }

    #[tokio::test]
    async fn an_allow_list_passes_only_what_it_names() {
        let f = filter(&["github.com", "*.github.com"], &[]);
        assert_matches!(verdict(&f, "https://github.com/x").await, FilterVerdict::Allow);
        assert_matches!(verdict(&f, "https://api.github.com/x").await, FilterVerdict::Allow);
        assert_matches!(verdict(&f, "https://example.com/x").await, FilterVerdict::Deny { .. });
        assert_matches!(verdict(&f, "https://notgithub.com/x").await, FilterVerdict::Deny { .. });
    }

    #[tokio::test]
    async fn an_entry_names_its_ports_and_the_scheme_default_is_the_port() {
        let f = filter(&["docs.example.org:80,443"], &[]);
        assert_matches!(verdict(&f, "http://docs.example.org/x").await, FilterVerdict::Allow);
        assert_matches!(verdict(&f, "https://docs.example.org/x").await, FilterVerdict::Allow);
        assert_matches!(verdict(&f, "https://docs.example.org:8443/x").await, FilterVerdict::Deny { .. });
        let tls_only = filter(&["docs.example.org"], &[]);
        assert_matches!(verdict(&tls_only, "http://docs.example.org/x").await, FilterVerdict::Deny { .. });
    }

    #[tokio::test]
    async fn a_block_wins_and_nothing_attached_passes_everything() {
        let f = filter(&["*.example.com"], &["evil.example.com"]);
        assert_matches!(verdict(&f, "https://safe.example.com/x").await, FilterVerdict::Allow);
        assert_matches!(verdict(&f, "https://evil.example.com/x").await, FilterVerdict::Deny { .. });
        let block_only = filter(&[], &["pastebin.com"]);
        assert_matches!(verdict(&block_only, "https://pastebin.com/x").await, FilterVerdict::Deny { .. });
        assert_matches!(verdict(&block_only, "https://pastebin.com./x").await, FilterVerdict::Deny { .. });
        assert_matches!(verdict(&block_only, "https://example.org/x").await, FilterVerdict::Allow);
        assert_matches!(verdict(&block_only, "http://pastebin.com/x").await, FilterVerdict::Deny { .. }, "every port");
        assert_matches!(verdict(&block_only, "https://pastebin.com:8443/x").await, FilterVerdict::Deny { .. });
        let tls_block = filter(&[], &["pastebin.com:443"]);
        assert_matches!(verdict(&tls_block, "http://pastebin.com/x").await, FilterVerdict::Allow, "stated ports only");
        assert!(filter(&[], &[]).is_inert());
        assert!(!block_only.is_inert());
    }

    #[tokio::test]
    async fn an_address_entry_matches_an_ip_literal_url_only() {
        let f = filter(&["93.184.216.0/24", "[2001:db8::]/32"], &[]);
        assert_matches!(verdict(&f, "https://93.184.216.34/x").await, FilterVerdict::Allow);
        assert_matches!(verdict(&f, "https://[2001:db8::1]/x").await, FilterVerdict::Allow);
        assert_matches!(verdict(&f, "https://93.184.217.1/x").await, FilterVerdict::Deny { .. });
        assert_matches!(verdict(&f, "https://example.com/x").await, FilterVerdict::Deny { .. });
    }

    #[tokio::test]
    async fn an_unreadable_blocked_entry_refuses_every_url_and_an_unreadable_allowed_one_is_left_out() {
        let lists = |allow: &[&str], block: &[&str]| crate::web::settings::WebDestinationLists {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            block: block.iter().map(|s| s.to_string()).collect(),
            allow_attached: !allow.is_empty(),
        };
        let blocked = DestinationListFilter::new(WebDestinations::from_lists(&lists(&[], &["a.lan", "not an entry"])));
        assert!(!blocked.is_inert());
        assert_matches!(verdict(&blocked, "https://example.org/").await, FilterVerdict::Deny { .. });
        let readable = DestinationListFilter::new(WebDestinations::from_lists(&lists(&[], &["a.lan"])));
        assert_matches!(verdict(&readable, "https://example.org/").await, FilterVerdict::Allow, "the positive control");
        let allowed = DestinationListFilter::new(WebDestinations::from_lists(&lists(&["b.lan", "not an entry"], &[])));
        assert_matches!(verdict(&allowed, "https://b.lan/").await, FilterVerdict::Allow);
        assert_matches!(verdict(&allowed, "https://c.lan/").await, FilterVerdict::Deny { .. });
        let unreadable_only = DestinationListFilter::new(WebDestinations::from_lists(&lists(&["not an entry"], &[])));
        assert_matches!(verdict(&unreadable_only, "https://c.lan/").await, FilterVerdict::Deny { .. },
            "an allow list none of whose entries reads passes nothing");
    }

    #[tokio::test]
    async fn an_attached_allow_list_with_no_entries_passes_nothing() {
        let empty = crate::web::settings::WebDestinationLists { allow: vec![], block: vec![], allow_attached: true };
        let f = DestinationListFilter::new(WebDestinations::from_lists(&empty));
        assert!(!f.is_inert());
        assert_matches!(verdict(&f, "https://example.org/").await, FilterVerdict::Deny { .. });
        let none = DestinationListFilter::new(WebDestinations::from_lists(&Default::default()));
        assert_matches!(verdict(&none, "https://example.org/").await, FilterVerdict::Allow, "the positive control");
    }

    #[tokio::test]
    async fn blocked_lists_flattened_past_one_lists_cap_still_block() {
        let block: Vec<String> = (0..=streamscope_client_templates::destination::MAX_ENTRIES)
            .map(|i| format!("h{i}.lan"))
            .collect();
        let lists = crate::web::settings::WebDestinationLists { allow: vec![], block, allow_attached: false };
        let f = DestinationListFilter::new(WebDestinations::from_lists(&lists));
        assert_matches!(verdict(&f, "https://h0.lan/").await, FilterVerdict::Deny { .. });
        assert_matches!(verdict(&f, "https://example.org/").await, FilterVerdict::Allow);
    }

    #[tokio::test]
    async fn a_url_without_a_host_is_refused() {
        let f = filter(&[], &[]);
        match verdict(&f, "data:text/plain,hello").await {
            FilterVerdict::Deny { reason } => assert!(reason.contains("no host")),
            v => panic!("expected deny, got {v:?}"),
        }
    }
}
