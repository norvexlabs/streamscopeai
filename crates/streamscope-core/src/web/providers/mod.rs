//! Backend implementations. Phase 1 ships SearXNG only; the other four
//! providers (Brave, Tavily, Google CSE, Serper) land in phase 2 with the
//! same `Backend` enum dispatch in [`super::backend`].

pub mod searxng;
