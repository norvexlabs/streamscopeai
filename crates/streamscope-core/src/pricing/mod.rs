//! Generic pricing: what a provider counts, and what each count costs.
//!
//! Two halves that meet in [`Rates::cost`]:
//!
//! * [`Units`] — the **measured** side. What the provider reported it counted
//!   for one request. Always read from the provider's own response; never
//!   recomputed by us. Vendors already convert modalities into their billing
//!   units their own way (fixed tokens per image, per second of audio), and the
//!   result is inside the counts they return, so recomputing produces a
//!   plausible number that is not the one being invoiced.
//! * [`Rates`] — the **priced** side. A map from unit to price, plus the
//!   currency those prices are quoted in. Data, not code: a provider inventing
//!   a new way to charge is a seed refresh, not a release.
//!
//! Adding a billing dimension therefore means adding a [`Unit`] variant,
//! populating it where the provider reports it, and seeding a rate.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

/// How a unit's stored rate relates to one unit of it.
///
/// The stored number is always in the unit's **natural** scale — what price
/// feeds publish and what an operator types. Text prices (tokens, characters)
/// are quoted per million; everything else per single unit. The fold divides by
/// this exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scale {
    /// The rate is quoted per 1,000,000 units.
    PerMillion,
    /// The rate is quoted per single unit.
    PerUnit,
}

impl Scale {
    /// Divisor applied to the counted units before multiplying by the rate.
    pub const fn divisor(self) -> f64 {
        match self {
            Scale::PerMillion => 1_000_000.0,
            Scale::PerUnit => 1.0,
        }
    }
}

/// One thing a provider counts and charges for.
///
/// A closed vocabulary. Each variant declares its wire key, its [`Scale`] and
/// its [`Unit::partition`] in ONE place, because each of those is an axis where
/// a wrong answer still produces a plausible number: a wrong divisor mis-bills
/// by a factor of a million, and a missed partition bills the same tokens
/// twice.
///
/// Declaration order is the JSON key order — keep related units adjacent so a
/// serialized rate map reads sensibly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unit {
    /// Prompt tokens, inclusive of every token unit that [`Unit::partition`]s
    /// into it.
    InputToken,
    /// Completion tokens, inclusive of every token unit that partitions into
    /// it. Reasoning tokens are part of this count, not a unit of their own:
    /// every provider bills them at the output rate.
    OutputToken,
    /// Prompt tokens written into the provider's prompt cache, at its default
    /// lifetime.
    CacheWriteToken,
    /// Prompt tokens written into a 1-hour prompt cache, which Anthropic bills
    /// apart from (and above) the default lifetime's writes.
    CacheWrite1hToken,
    /// Prompt tokens served from the provider's prompt cache.
    CacheReadToken,
    /// Prompt tokens that carried audio.
    AudioInputToken,
    /// Completion tokens that carried audio.
    AudioOutputToken,
    /// Characters of input text, counted as Unicode scalar values.
    ///
    /// The dimension text-to-speech is billed in: the response is audio and
    /// carries no usage at all, so the request's own text is the only thing
    /// there is to count. A TTS model priced per token instead publishes no
    /// rate for this and stays unpriced-and-badged rather than mismeasured.
    InputCharacter,
    /// Images the model produced.
    ImageOutput,
    /// Seconds of audio, on the audio endpoints.
    AudioSecond,
    /// Seconds of video, on the video endpoints.
    VideoSecond,
}

/// A unit carved out of a larger count, and what it costs when the provider
/// publishes no separate price for it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Partition {
    /// The count this unit is reported *inside*.
    pub parent: Unit,
    /// Multiple of the parent's rate to charge when this unit has no rate of
    /// its own. A partitioned unit is therefore priced whenever its parent is.
    pub fallback_multiplier: f64,
}

impl Unit {
    /// Every unit, in declaration order.
    ///
    /// The vocabulary holds only units the gateway can actually measure. A rate
    /// for something nothing counts would sit in the map forever contributing
    /// nothing, and a unit emitted on every request whether or not the provider
    /// charges for it would badge every model as unpriced.
    pub const ALL: [Unit; 11] = [
        Unit::InputToken,
        Unit::OutputToken,
        Unit::CacheWriteToken,
        Unit::CacheWrite1hToken,
        Unit::CacheReadToken,
        Unit::AudioInputToken,
        Unit::AudioOutputToken,
        Unit::InputCharacter,
        Unit::ImageOutput,
        Unit::AudioSecond,
        Unit::VideoSecond,
    ];

    /// Stable key used by the seed, the database and the API. Never rename one:
    /// a renamed key silently reads as an unknown unit, which drops the rate.
    pub const fn wire(self) -> &'static str {
        match self {
            Unit::InputToken => "input_token",
            Unit::OutputToken => "output_token",
            Unit::CacheWriteToken => "cache_write_token",
            Unit::CacheWrite1hToken => "cache_write_1h_token",
            Unit::CacheReadToken => "cache_read_token",
            Unit::AudioInputToken => "audio_input_token",
            Unit::AudioOutputToken => "audio_output_token",
            Unit::InputCharacter => "input_character",
            Unit::ImageOutput => "image_output",
            Unit::AudioSecond => "audio_second",
            Unit::VideoSecond => "video_second",
        }
    }

    /// Parse a wire key. An unrecognised key is not an error at the call sites
    /// that matter — a rate map written by a newer admin is folded in with the
    /// unknown entries dropped, exactly as an unknown profile kind is.
    pub fn from_wire(key: &str) -> Option<Unit> {
        Unit::ALL.into_iter().find(|u| u.wire() == key)
    }

    /// The scale the rate for this unit is quoted in.
    pub const fn scale(self) -> Scale {
        match self {
            Unit::InputToken
            | Unit::OutputToken
            | Unit::CacheWriteToken
            | Unit::CacheWrite1hToken
            | Unit::CacheReadToken
            | Unit::AudioInputToken
            | Unit::AudioOutputToken
            // Character prices are published per million too ($15/1M is how
            // every TTS vendor quotes them), so this is a text unit by scale
            // even though it is not a token.
            | Unit::InputCharacter => Scale::PerMillion,
            Unit::ImageOutput | Unit::AudioSecond | Unit::VideoSecond => Scale::PerUnit,
        }
    }

    /// The count this unit is reported inside, if any.
    ///
    /// Providers fold sub-counts INTO their headline counts: `prompt_tokens`
    /// already contains the cached tokens and the audio tokens. Billing both
    /// the parent and the child charges the same tokens twice, so the fold
    /// subtracts every child from its parent before pricing either.
    pub const fn partition(self) -> Option<Partition> {
        match self {
            // Cache reads are ~0.1x input and writes ~1.25x across providers.
            // Charging an unpriced cache read at the full input rate over-bills
            // cached traffic tenfold, and most catalog entries omit cache prices.
            Unit::CacheWriteToken => Some(Partition {
                parent: Unit::InputToken,
                fallback_multiplier: 1.25,
            }),
            // A 1-hour write is 2x input on Anthropic, the one provider that
            // reports it.
            Unit::CacheWrite1hToken => Some(Partition {
                parent: Unit::InputToken,
                fallback_multiplier: 2.0,
            }),
            Unit::CacheReadToken => Some(Partition {
                parent: Unit::InputToken,
                fallback_multiplier: 0.1,
            }),
            // Audio tokens are ordinary tokens unless the provider prices them
            // apart, so an absent audio rate must charge the parent's rate —
            // not zero, which subtracting the partition would otherwise produce.
            Unit::AudioInputToken => Some(Partition {
                parent: Unit::InputToken,
                fallback_multiplier: 1.0,
            }),
            Unit::AudioOutputToken => Some(Partition {
                parent: Unit::OutputToken,
                fallback_multiplier: 1.0,
            }),
            _ => None,
        }
    }
}

impl Serialize for Unit {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.wire())
    }
}

impl<'de> Deserialize<'de> for Unit {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let key = String::deserialize(d)?;
        Unit::from_wire(&key)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown pricing unit {key}")))
    }
}

/// A price threshold: above `above` units of the tiering basis, `rate` applies.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Tier {
    /// Basis count this tier takes effect strictly above.
    pub above: u64,
    /// Rate for the whole request once the basis exceeds `above`.
    pub rate: f64,
}

/// What one unit costs, in the rate map's currency and the unit's natural scale.
///
/// Tiering is the only case that needs more than a scalar, and it is a step
/// table rather than an expression: keeping it declarative is what lets a price
/// change ship as a seed refresh instead of a release.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum Rate {
    /// One price, whatever the request size.
    Flat(f64),
    /// A base price plus thresholds on the request's prompt size.
    Tiered {
        /// Price below the first threshold.
        rate: f64,
        /// Thresholds, applied by the highest one the basis exceeds.
        tiers: Vec<Tier>,
    },
}

impl Rate {
    /// The applicable price for a request whose tiering basis is `basis`.
    ///
    /// `basis` is the request's raw [`Unit::InputToken`] count — tiering in the
    /// wild is on prompt size (a long-context surcharge), and the raw count is
    /// what the provider compares against, before any partition subtraction.
    pub fn resolve(&self, basis: u64) -> f64 {
        match self {
            Rate::Flat(r) => *r,
            Rate::Tiered { rate, tiers } => tiers
                .iter()
                .filter(|t| basis > t.above)
                .max_by_key(|t| t.above)
                .map_or(*rate, |t| t.rate),
        }
    }
}

/// An ISO 4217 currency code.
///
/// Three ASCII letters, held inline so the type stays `Copy` and comparisons
/// are trivial. Not an enum: the set of currencies an operator may price in is
/// not ours to close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Currency([u8; 3]);

impl Currency {
    /// The default quoting currency.
    pub const USD: Currency = Currency(*b"USD");

    /// Parse a three-letter code, uppercasing it. Anything else is rejected —
    /// a currency we cannot name is not one we may silently treat as dollars.
    pub fn parse(code: &str) -> Option<Currency> {
        let bytes = code.trim().as_bytes();
        if bytes.len() != 3 || !bytes.iter().all(|b| b.is_ascii_alphabetic()) {
            return None;
        }
        let mut out = [0u8; 3];
        for (slot, b) in out.iter_mut().zip(bytes) {
            *slot = b.to_ascii_uppercase();
        }
        Some(Currency(out))
    }

    /// The code as a string.
    pub fn as_str(&self) -> &str {
        // Every byte is ASCII alphabetic by construction.
        std::str::from_utf8(&self.0).unwrap_or("USD")
    }
}

impl Default for Currency {
    fn default() -> Self {
        Currency::USD
    }
}

impl TryFrom<String> for Currency {
    type Error = String;

    fn try_from(code: String) -> Result<Self, Self::Error> {
        Currency::parse(&code).ok_or_else(|| format!("invalid currency code {code}"))
    }
}

impl std::fmt::Display for Currency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Currency {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Currency {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let code = String::deserialize(d)?;
        Currency::parse(&code)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid currency code {code}")))
    }
}

/// What one request consumed, as the provider counted it.
///
/// Counts are stored exactly as reported, which means a parent count still
/// contains its partitions; [`Rates::cost`] is what subtracts them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Units(BTreeMap<Unit, u64>);

impl Units {
    /// An empty measurement.
    pub fn new() -> Self {
        Units(BTreeMap::new())
    }

    /// Record `count` of `unit`, adding to anything already recorded. A zero
    /// count is dropped rather than stored, so an absent unit and a zeroed one
    /// stay the same thing.
    pub fn add(&mut self, unit: Unit, count: u64) {
        if count == 0 {
            return;
        }
        *self.0.entry(unit).or_insert(0) += count;
    }

    /// Builder form of [`Units::add`].
    #[must_use]
    pub fn with(mut self, unit: Unit, count: u64) -> Self {
        self.add(unit, count);
        self
    }

    /// The count reported for `unit`, or zero.
    pub fn get(&self, unit: Unit) -> u64 {
        self.0.get(&unit).copied().unwrap_or(0)
    }

    /// Whether nothing was measured.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every measured unit and its count, in unit declaration order.
    pub fn iter(&self) -> impl Iterator<Item = (Unit, u64)> + '_ {
        self.0.iter().map(|(u, n)| (*u, *n))
    }
}

/// Prices for one model, and the currency they are quoted in.
///
/// Deliberately has no `Default`: an empty rate map means *no price is known*,
/// while a request the client funded elsewhere is *known to be free*, and the
/// two must never be reachable by the same expression. Construct through
/// [`Rates::unknown`] or [`Rates::free`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Rates {
    /// Price per unit, in `currency`, at each unit's natural scale. Keys are
    /// pricing-unit wire names; an unrecognised one is dropped rather than
    /// rejected, so a rate map written by a newer build still loads.
    #[serde(default, deserialize_with = "deserialize_rate_map")]
    #[schema(value_type = std::collections::BTreeMap<String, Rate>)]
    pub units: BTreeMap<Unit, Rate>,
    /// Currency every rate above is quoted in. Travels inside the rate map so
    /// prices and their currency are inherited as one atom — a row can never
    /// take its numbers from the catalog and its currency from somewhere else.
    #[serde(default)]
    #[schema(value_type = String, example = "USD")]
    pub currency: Currency,
    /// Every unit is free, deliberately: the client funded the call on its own
    /// provider account, or the gateway served the answer from its cache.
    /// Not persisted — it is a property of the request, not of the model.
    #[serde(skip)]
    pub zero_rated: bool,
}

/// Tolerate a rate map written by a newer admin: an entry naming a unit this
/// build does not know is dropped, exactly as an unknown profile kind is at
/// config fold-in, rather than failing the whole snapshot.
fn deserialize_rate_map<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<Unit, Rate>, D::Error> {
    let raw = BTreeMap::<String, Rate>::deserialize(d)?;
    Ok(raw
        .into_iter()
        .filter_map(|(k, v)| Unit::from_wire(&k).map(|u| (u, v)))
        .collect())
}

/// Per-unit decomposition of one charge, keyed by billing unit.
pub type BilledUnits = BTreeMap<Unit, BilledUnit>;

/// Read a stored breakdown, dropping any line naming a unit this build does not
/// know.
///
/// The tolerance matters here more than on a rate map: this decodes rows that
/// are already on disk. A newer release can write a unit an older one has never
/// heard of, and after an A/B rollback that older binary must still be able to
/// read its own audit trail — erroring would fail the whole query and take every
/// other row on the page with it.
pub fn deserialize_billed_units<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<BilledUnits, D::Error> {
    let raw = BTreeMap::<String, BilledUnit>::deserialize(d)?;
    Ok(raw
        .into_iter()
        .filter_map(|(k, v)| Unit::from_wire(&k).map(|u| (u, v)))
        .collect())
}

/// One line of a priced request: how much of a unit was charged, and for how
/// much.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BilledUnit {
    /// Units charged — the count reported by the provider **less** anything
    /// that partitions out of it, since those are charged on their own line.
    pub count: u64,
    /// What that count cost, in the enclosing [`Cost`]'s currency.
    pub cost: f64,
}

/// The outcome of pricing one request.
#[derive(Debug, Clone, PartialEq)]
pub struct Cost {
    /// Total, in [`Cost::currency`]. Always equals the sum of [`Cost::lines`].
    pub amount: f64,
    /// Currency the total is expressed in.
    pub currency: Currency,
    /// Per-unit decomposition of the total.
    pub lines: BTreeMap<Unit, BilledUnit>,
    /// Units the request consumed that carried no price, directly or through a
    /// partition parent. Non-empty means the total is a floor, not a figure.
    pub unpriced: Vec<Unit>,
}

impl Cost {
    /// Whether every unit the request consumed carried a price.
    pub fn is_known(&self) -> bool {
        self.unpriced.is_empty()
    }

    /// Restate the cost in another currency using an operator-configured rate.
    /// `None` when the pair is not configured — a spend figure converted at a
    /// guessed rate is worse than one left in the currency it was quoted in.
    pub fn convert(&self, to: Currency, fx: &FxTable) -> Option<Cost> {
        let rate = fx.rate(self.currency, to)?;
        Some(Cost {
            amount: self.amount * rate,
            currency: to,
            lines: self
                .lines
                .iter()
                .map(|(u, l)| {
                    (
                        *u,
                        BilledUnit {
                            count: l.count,
                            cost: l.cost * rate,
                        },
                    )
                })
                .collect(),
            unpriced: self.unpriced.clone(),
        })
    }
}

impl Rates {
    /// No price is known for this model. A request against it is billed at a
    /// floor of zero and badged, so the traffic stays visible instead of being
    /// silently reported as free.
    pub fn unknown() -> Self {
        Rates {
            units: BTreeMap::new(),
            currency: Currency::USD,
            zero_rated: false,
        }
    }

    /// Known to cost nothing: bring-your-own-key traffic, where the client's
    /// own provider account was charged, and cache hits, where no upstream call
    /// happened at all. Genuinely free, not unknown.
    pub fn free() -> Self {
        Rates {
            units: BTreeMap::new(),
            currency: Currency::USD,
            zero_rated: true,
        }
    }

    /// Build from a wire map, keeping only units this build knows.
    pub fn from_units(units: BTreeMap<Unit, Rate>, currency: Currency) -> Self {
        Rates {
            units,
            currency,
            zero_rated: false,
        }
    }

    /// Whether any price at all is on file.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// The price for one unit at a given tiering basis, following the unit's
    /// partition fallback when it carries no rate of its own.
    fn rate_for(&self, unit: Unit, basis: u64) -> Option<f64> {
        if let Some(r) = self.units.get(&unit) {
            return Some(r.resolve(basis));
        }
        let p = unit.partition()?;
        let parent = self.units.get(&p.parent)?;
        Some(parent.resolve(basis) * p.fallback_multiplier)
    }

    /// Price a measured request and restate it in the tenant's accounting
    /// currency.
    pub fn bill(&self, units: &Units, accounting: Currency, fx: &FxTable) -> Billing {
        // A charge of nothing converts exactly into any currency, so traffic the
        // client funded elsewhere must not depend on the operator having
        // configured a rate between the ledger and whatever currency an empty
        // rate map happens to name. Without this, a tenant keeping its books in
        // euros — and therefore with no reason to configure a dollar pair — would
        // see every bring-your-own-key, cache-hit and inline-analyzed row badged
        // as unpriced: precisely the rows that are *known* to be free.
        if self.zero_rated {
            return Billing::zero(accounting);
        }
        let source = self.cost(units);
        let fx_rate = fx.rate(source.currency, accounting);
        Billing {
            accounting,
            accounted: fx_rate.map(|r| Cost {
                amount: source.amount * r,
                currency: accounting,
                lines: source
                    .lines
                    .iter()
                    .map(|(u, l)| {
                        (
                            *u,
                            BilledUnit {
                                count: l.count,
                                cost: l.cost * r,
                            },
                        )
                    })
                    .collect(),
                unpriced: source.unpriced.clone(),
            }),
            fx_rate: fx_rate.unwrap_or(1.0),
            source,
        }
    }

    /// Price a measured request.
    ///
    /// Partitions are subtracted from their parents first, because providers
    /// report a parent count inclusive of its children; pricing both charges
    /// the same tokens twice.
    pub fn cost(&self, units: &Units) -> Cost {
        if self.zero_rated {
            return Cost {
                amount: 0.0,
                currency: self.currency,
                lines: BTreeMap::new(),
                unpriced: Vec::new(),
            };
        }

        // Tiering is on the request's prompt size as the provider saw it, so
        // the basis is the raw count, before partitions are taken out.
        let basis = units.get(Unit::InputToken);

        let mut amount = 0.0;
        let mut lines = BTreeMap::new();
        let mut unpriced = Vec::new();
        for unit in Unit::ALL {
            let reported = units.get(unit);
            // A parent is charged only for what is left once its children are
            // removed; a child whose parent under-reports cannot go negative.
            let children: u64 = Unit::ALL
                .into_iter()
                .filter(|c| c.partition().is_some_and(|p| p.parent == unit))
                .map(|c| units.get(c))
                .sum();
            let billable = reported.saturating_sub(children);
            if billable == 0 {
                continue;
            }
            match self.rate_for(unit, basis) {
                Some(rate) => {
                    let cost = (billable as f64 / unit.scale().divisor()) * rate;
                    amount += cost;
                    lines.insert(
                        unit,
                        BilledUnit {
                            count: billable,
                            cost,
                        },
                    );
                }
                None => unpriced.push(unit),
            }
        }

        Cost {
            amount,
            currency: self.currency,
            lines,
            unpriced,
        }
    }
}

/// One request's charge, stated both as the provider quotes it and as the
/// tenant's ledger records it.
#[derive(Debug, Clone, PartialEq)]
pub struct Billing {
    /// What the provider charges, in the currency it quotes.
    pub source: Cost,
    /// The currency the tenant keeps its books in. Always set, including when
    /// the charge could not be expressed in it — the ledger's unit does not
    /// depend on whether one particular row could be converted into it.
    pub accounting: Currency,
    /// The same charge in [`Self::accounting`]. `None` when the operator has
    /// configured no rate for the pair: a spend figure converted at a guessed
    /// rate is worse than one the ledger declines to state.
    pub accounted: Option<Cost>,
    /// Multiplier that took `source` to `accounted`. One when no conversion was
    /// needed, and one when none was available.
    pub fx_rate: f64,
}

impl Billing {
    /// Amount for the ledger, in the accounting currency. Zero when the charge
    /// cannot be stated there — the same treatment an unpriced model gets, and
    /// for the same reason: a number nobody can stand behind must not move a
    /// budget.
    pub fn amount(&self) -> f64 {
        self.accounted.as_ref().map_or(0.0, |c| c.amount)
    }

    /// Whether every consumed unit had a price AND that price could be stated
    /// in the accounting currency. False raises the unpriced badge.
    pub fn is_known(&self) -> bool {
        self.source.is_known() && self.accounted.is_some()
    }

    /// The per-unit decomposition to record on the audit row: the accounted
    /// lines, or none at all when the charge could not be stated in the ledger's
    /// currency. Never the source lines — they are denominated in a different
    /// currency, and filing them under the accounting one would misreport them.
    pub fn accounted_lines(&self) -> BTreeMap<Unit, BilledUnit> {
        self.accounted
            .as_ref()
            .map(|c| c.lines.clone())
            .unwrap_or_default()
    }

    /// The same charge reduced to nothing, keeping both currencies and the rate
    /// that relates them. Used where a request is refunded after pricing — the
    /// amount becomes zero, but which currencies were involved is still a true
    /// fact about the row, and restating them as the ledger's own would report a
    /// euro-priced model as dollar-priced.
    pub fn zeroed(&self) -> Self {
        let nothing = |c: Currency| Cost {
            amount: 0.0,
            currency: c,
            lines: BTreeMap::new(),
            unpriced: Vec::new(),
        };
        Billing {
            source: nothing(self.source.currency),
            accounting: self.accounting,
            accounted: self.accounted.as_ref().map(|c| nothing(c.currency)),
            fx_rate: self.fx_rate,
        }
    }

    /// A charge of nothing, in the accounting currency.
    pub fn zero(accounting: Currency) -> Self {
        let nothing = || Cost {
            amount: 0.0,
            currency: accounting,
            lines: BTreeMap::new(),
            unpriced: Vec::new(),
        };
        Billing {
            source: nothing(),
            accounting,
            accounted: Some(nothing()),
            fx_rate: 1.0,
        }
    }
}

/// Tenant-wide accounting settings: the currency the books are kept in, and the
/// table for converting a provider's quote into it.
///
/// One struct rather than two loose values because they are only ever meaningful
/// together — a conversion table without a target currency converts to nothing,
/// and a target currency without a table can only be honoured for models already
/// quoted in it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PricingSettings {
    /// Currency every budget cap, spend aggregate and audit total is expressed
    /// in.
    #[serde(default)]
    #[schema(value_type = String, example = "USD")]
    pub accounting_currency: Currency,
    /// Operator-maintained conversion rates, `{from: {to: multiplier}}`.
    #[serde(default)]
    #[schema(value_type = std::collections::BTreeMap<String, std::collections::BTreeMap<String, f64>>)]
    pub fx: FxTable,
}

/// Operator-maintained conversion rates between currencies.
///
/// Never a live feed: an air-gapped deployment is a supported shape, and a rate
/// that moves on its own would make last month's spend move with it. A pair
/// with no configured rate is left unconverted and badged rather than converted
/// at a guess.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FxTable(BTreeMap<String, BTreeMap<String, f64>>);

impl FxTable {
    /// Multiplier taking one unit of `from` to `to`, or `None` when the
    /// operator has not configured that pair.
    pub fn rate(&self, from: Currency, to: Currency) -> Option<f64> {
        if from == to {
            return Some(1.0);
        }
        let direct = self
            .0
            .get(from.as_str())
            .and_then(|m| m.get(to.as_str()))
            .copied();
        if let Some(r) = direct.filter(|r| r.is_finite() && *r > 0.0) {
            return Some(r);
        }
        // A single configured direction is enough: the inverse of a positive
        // finite rate is exact enough for money at this resolution, and making
        // an operator enter both halves invites the two disagreeing.
        self.0
            .get(to.as_str())
            .and_then(|m| m.get(from.as_str()))
            .copied()
            .filter(|r| r.is_finite() && *r > 0.0)
            .map(|r| 1.0 / r)
    }

    /// Convert an amount, or `None` when the pair is not configured.
    pub fn convert(&self, amount: f64, from: Currency, to: Currency) -> Option<f64> {
        self.rate(from, to).map(|r| amount * r)
    }

    /// Whether the operator has configured anything at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Build from an operator-supplied `{from: {to: rate}}` map, normalising the
    /// currency codes and dropping any pair that is not a usable rate. Returns
    /// the rejected entries so the caller can refuse the write rather than
    /// silently storing a table with holes in it.
    pub fn from_map(
        raw: &BTreeMap<String, BTreeMap<String, f64>>,
    ) -> (FxTable, Vec<String>) {
        let mut table: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
        let mut rejected = Vec::new();
        for (from, targets) in raw {
            let Some(from_c) = Currency::parse(from) else {
                rejected.push(from.clone());
                continue;
            };
            for (to, rate) in targets {
                let Some(to_c) = Currency::parse(to) else {
                    rejected.push(to.clone());
                    continue;
                };
                if !rate.is_finite() || *rate <= 0.0 {
                    rejected.push(format!("{from_c}->{to_c}"));
                    continue;
                }
                table
                    .entry(from_c.as_str().to_string())
                    .or_default()
                    .insert(to_c.as_str().to_string(), *rate);
            }
        }
        (FxTable(table), rejected)
    }

    /// The configured pairs, for display.
    pub fn as_map(&self) -> &BTreeMap<String, BTreeMap<String, f64>> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rates(pairs: &[(Unit, f64)]) -> Rates {
        Rates::from_units(
            pairs.iter().map(|(u, r)| (*u, Rate::Flat(*r))).collect(),
            Currency::USD,
        )
    }

    #[test]
    fn every_partition_parent_exists_and_no_cycle() {
        for unit in Unit::ALL {
            let Some(p) = unit.partition() else { continue };
            assert!(
                Unit::ALL.contains(&p.parent),
                "{:?} partitions into a unit outside the vocabulary",
                unit
            );
            assert_ne!(p.parent, unit, "{unit:?} partitions into itself");
            // One level only: a parent that is itself partitioned would make
            // the single subtraction pass in `cost` wrong.
            assert!(
                p.parent.partition().is_none(),
                "{:?} partitions into {:?}, which is itself partitioned",
                unit,
                p.parent
            );
            assert!(
                p.fallback_multiplier.is_finite() && p.fallback_multiplier >= 0.0,
                "{unit:?} has a nonsensical fallback multiplier"
            );
        }
    }

    #[test]
    fn wire_keys_are_unique_and_round_trip() {
        let mut seen = std::collections::HashSet::new();
        for unit in Unit::ALL {
            assert!(seen.insert(unit.wire()), "duplicate wire key {}", unit.wire());
            assert_eq!(Unit::from_wire(unit.wire()), Some(unit));
        }
        assert_eq!(Unit::from_wire("no_such_unit"), None);
    }

    #[test]
    fn tokens_are_priced_per_million_and_others_per_unit() {
        let r = rates(&[(Unit::InputToken, 3.0), (Unit::ImageOutput, 0.04)]);
        let cost = r.cost(&Units::new().with(Unit::InputToken, 1_000_000));
        assert!((cost.amount - 3.0).abs() < 1e-9, "{}", cost.amount);

        let cost = r.cost(&Units::new().with(Unit::ImageOutput, 3));
        assert!((cost.amount - 0.12).abs() < 1e-9, "{}", cost.amount);
    }

    #[test]
    fn a_partition_is_subtracted_from_its_parent() {
        // 1M prompt tokens of which 200k were cache writes and 300k cache reads:
        // only 500k are charged at the input rate.
        let r = rates(&[
            (Unit::InputToken, 10.0),
            (Unit::CacheWriteToken, 12.5),
            (Unit::CacheReadToken, 1.0),
        ]);
        let cost = r.cost(
            &Units::new()
                .with(Unit::InputToken, 1_000_000)
                .with(Unit::CacheWriteToken, 200_000)
                .with(Unit::CacheReadToken, 300_000),
        );
        let expected = 0.5 * 10.0 + 0.2 * 12.5 + 0.3 * 1.0;
        assert!((cost.amount - expected).abs() < 1e-9, "{}", cost.amount);
    }

    #[test]
    fn billing_a_parent_and_its_child_separately_would_double_charge() {
        // The same measurement priced without the subtraction — what the fold
        // must not do.
        let r = rates(&[(Unit::InputToken, 10.0), (Unit::CacheReadToken, 1.0)]);
        let units = Units::new()
            .with(Unit::InputToken, 1_000_000)
            .with(Unit::CacheReadToken, 1_000_000);
        // Every prompt token was a cache read, so nothing is charged at the
        // input rate at all.
        let cost = r.cost(&units);
        assert!((cost.amount - 1.0).abs() < 1e-9, "{}", cost.amount);
    }

    #[test]
    fn an_unpriced_partition_falls_back_to_a_multiple_of_its_parent() {
        let r = rates(&[(Unit::InputToken, 10.0)]);
        let cost = r.cost(
            &Units::new()
                .with(Unit::InputToken, 1_000_000)
                .with(Unit::CacheReadToken, 500_000),
        );
        // 500k at the input rate + 500k at 0.1x it.
        let expected = 0.5 * 10.0 + 0.5 * 1.0;
        assert!((cost.amount - expected).abs() < 1e-9, "{}", cost.amount);
        assert!(cost.is_known(), "a fallback price is still a price");
    }

    #[test]
    fn unpriced_audio_tokens_cost_what_ordinary_tokens_cost() {
        // Subtracting the partition without a fallback would make audio tokens
        // free, which is worse than the pre-split behaviour.
        let r = rates(&[(Unit::InputToken, 10.0)]);
        let with_audio = r.cost(
            &Units::new()
                .with(Unit::InputToken, 1_000_000)
                .with(Unit::AudioInputToken, 400_000),
        );
        let without = r.cost(&Units::new().with(Unit::InputToken, 1_000_000));
        assert!(
            (with_audio.amount - without.amount).abs() < 1e-9,
            "{} vs {}",
            with_audio.amount,
            without.amount
        );
    }

    #[test]
    fn a_separately_priced_audio_token_costs_its_own_rate() {
        let r = rates(&[(Unit::InputToken, 10.0), (Unit::AudioInputToken, 100.0)]);
        let cost = r.cost(
            &Units::new()
                .with(Unit::InputToken, 1_000_000)
                .with(Unit::AudioInputToken, 100_000),
        );
        let expected = 0.9 * 10.0 + 0.1 * 100.0;
        assert!((cost.amount - expected).abs() < 1e-9, "{}", cost.amount);
    }

    #[test]
    fn a_consumed_unit_with_no_rate_is_reported_unpriced() {
        let r = rates(&[(Unit::InputToken, 10.0)]);
        let cost = r.cost(
            &Units::new()
                .with(Unit::InputToken, 1_000_000)
                .with(Unit::VideoSecond, 30),
        );
        assert_eq!(cost.unpriced, vec![Unit::VideoSecond]);
        assert!(!cost.is_known());
        // The priced part is still charged — the total is a floor, not a zero.
        assert!((cost.amount - 10.0).abs() < 1e-9, "{}", cost.amount);
    }

    #[test]
    fn counts_must_reach_the_fold_inclusive_of_their_partitions() {
        // Anthropic's wire reports `input_tokens` as the NON-cached portion,
        // disjoint from the cache counts; the SSE parser normalises that to the
        // inclusive convention every other protocol uses. This is what that
        // normalisation is worth: hand the fold the raw exclusive number and the
        // subtraction removes the cache tokens a second time, silently
        // under-billing by the cache portion at the input rate.
        let r = rates(&[
            (Unit::InputToken, 3.0),
            (Unit::CacheWriteToken, 3.75),
            (Unit::CacheReadToken, 0.30),
        ]);
        let cached = |n| {
            Units::new()
                .with(Unit::InputToken, n)
                .with(Unit::CacheWriteToken, 100_000)
                .with(Unit::CacheReadToken, 50_000)
        };
        // Inclusive: 650k prompt tokens of which 150k were cache.
        let correct = r.cost(&cached(650_000));
        assert!((correct.amount - (1.5 + 0.375 + 0.015)).abs() < 1e-9);
        // Exclusive, as Anthropic sends it: 500k non-cached passed through raw.
        let underbilled = r.cost(&cached(500_000));
        let gap = correct.amount - underbilled.amount;
        assert!((gap - 0.45).abs() < 1e-9, "{gap}");
    }

    /// Anthropic bills a 1-hour cache write at 2x input and a 5-minute one at
    /// 1.25x: each lifetime is its own unit, and a 1-hour write with no rate
    /// of its own is priced at 2x input, never at the 5-minute rate.
    #[test]
    fn a_one_hour_cache_write_is_billed_apart_from_a_five_minute_one() {
        let usage = crate::api::domain::Usage {
            prompt_tokens: 650_000,
            cache_creation_tokens: Some(300_000),
            cache_creation_1h_tokens: Some(100_000),
            ..Default::default()
        };
        let units = usage.billed_units();
        assert_eq!(units.get(Unit::CacheWriteToken), 200_000);
        assert_eq!(units.get(Unit::CacheWrite1hToken), 100_000);

        let catalog = rates(&[(Unit::InputToken, 3.0), (Unit::CacheWriteToken, 3.75)]);
        // 350k input at $3, 200k 5-minute writes at $3.75, 100k 1-hour writes at 2 x $3.
        let cost = catalog.cost(&units);
        assert!((cost.amount - (1.05 + 0.75 + 0.6)).abs() < 1e-9, "{}", cost.amount);
        assert!(cost.unpriced.is_empty());
        // A listed 1-hour rate wins over the fallback.
        let listed = rates(&[(Unit::InputToken, 3.0), (Unit::CacheWriteToken, 3.75), (Unit::CacheWrite1hToken, 5.0)]);
        assert!((listed.cost(&units).amount - (1.05 + 0.75 + 0.5)).abs() < 1e-9);

        // A 1-hour count over the whole write count — which is what the
        // prompt count includes — is held to it.
        let over = crate::api::domain::Usage {
            cache_creation_tokens: Some(10),
            cache_creation_1h_tokens: Some(25),
            ..Default::default()
        };
        assert_eq!(over.billed_units().get(Unit::CacheWriteToken), 0);
        assert_eq!(over.billed_units().get(Unit::CacheWrite1hToken), 10);
    }

    #[test]
    fn the_breakdown_sums_to_the_total() {
        let r = rates(&[
            (Unit::InputToken, 10.0),
            (Unit::OutputToken, 30.0),
            (Unit::CacheReadToken, 1.0),
            (Unit::ImageOutput, 0.04),
        ]);
        let cost = r.cost(
            &Units::new()
                .with(Unit::InputToken, 900_000)
                .with(Unit::CacheReadToken, 400_000)
                .with(Unit::OutputToken, 50_000)
                .with(Unit::ImageOutput, 2),
        );
        let summed: f64 = cost.lines.values().map(|l| l.cost).sum();
        assert!((summed - cost.amount).abs() < 1e-12, "{summed} vs {}", cost.amount);
        assert_eq!(cost.lines.len(), 4);
    }

    #[test]
    fn a_billed_line_counts_what_was_charged_not_what_was_reported() {
        // 1M prompt tokens reported, 400k of them cache reads: the input line
        // must show the 600k it charged, not the 1M the provider reported, or
        // the breakdown contradicts the total.
        let r = rates(&[(Unit::InputToken, 10.0), (Unit::CacheReadToken, 1.0)]);
        let cost = r.cost(
            &Units::new()
                .with(Unit::InputToken, 1_000_000)
                .with(Unit::CacheReadToken, 400_000),
        );
        assert_eq!(cost.lines[&Unit::InputToken].count, 600_000);
        assert_eq!(cost.lines[&Unit::CacheReadToken].count, 400_000);
    }

    #[test]
    fn an_unpriced_unit_leaves_no_line() {
        let r = rates(&[(Unit::InputToken, 10.0)]);
        let cost = r.cost(
            &Units::new()
                .with(Unit::InputToken, 1_000_000)
                .with(Unit::VideoSecond, 30),
        );
        assert!(!cost.lines.contains_key(&Unit::VideoSecond));
        let summed: f64 = cost.lines.values().map(|l| l.cost).sum();
        assert!((summed - cost.amount).abs() < 1e-12);
    }

    #[test]
    fn converting_scales_every_line_with_the_total() {
        let fx: FxTable = serde_json::from_str(r#"{"EUR":{"USD":1.1}}"#).unwrap();
        let eur = Currency::parse("EUR").unwrap();
        let r = Rates::from_units(
            BTreeMap::from([
                (Unit::InputToken, Rate::Flat(10.0)),
                (Unit::OutputToken, Rate::Flat(30.0)),
            ]),
            eur,
        );
        let cost = r.cost(
            &Units::new()
                .with(Unit::InputToken, 1_000_000)
                .with(Unit::OutputToken, 1_000_000),
        );
        assert_eq!(cost.currency, eur);
        let usd = cost.convert(Currency::USD, &fx).unwrap();
        assert_eq!(usd.currency, Currency::USD);
        assert!((usd.amount - 44.0).abs() < 1e-9, "{}", usd.amount);
        let summed: f64 = usd.lines.values().map(|l| l.cost).sum();
        assert!((summed - usd.amount).abs() < 1e-12);
        assert_eq!(usd.lines[&Unit::InputToken].count, 1_000_000);
    }

    #[test]
    fn converting_without_a_configured_rate_yields_nothing() {
        let r = Rates::from_units(
            BTreeMap::from([(Unit::InputToken, Rate::Flat(10.0))]),
            Currency::parse("SEK").unwrap(),
        );
        let cost = r.cost(&Units::new().with(Unit::InputToken, 1_000_000));
        assert!(cost.convert(Currency::USD, &FxTable::default()).is_none());
    }

    #[test]
    fn billing_states_the_charge_in_both_currencies() {
        let fx: FxTable = serde_json::from_str(r#"{"EUR":{"USD":1.1}}"#).unwrap();
        let eur = Currency::parse("EUR").unwrap();
        let r = Rates::from_units(
            BTreeMap::from([(Unit::InputToken, Rate::Flat(10.0))]),
            eur,
        );
        let b = r.bill(
            &Units::new().with(Unit::InputToken, 1_000_000),
            Currency::USD,
            &fx,
        );
        assert_eq!(b.source.currency, eur);
        assert!((b.source.amount - 10.0).abs() < 1e-9);
        assert_eq!(b.fx_rate, 1.1);
        assert!((b.amount() - 11.0).abs() < 1e-9, "{}", b.amount());
        assert!(b.is_known());
    }

    #[test]
    fn a_charge_the_ledger_cannot_state_moves_no_money() {
        // The provider quotes in a currency the operator has configured no rate
        // for. The row still records what the provider charges, but the ledger
        // declines to invent a figure — and the request must not be reported as
        // free, which would let an enforcing budget pass it through.
        let r = Rates::from_units(
            BTreeMap::from([(Unit::InputToken, Rate::Flat(10.0))]),
            Currency::parse("SEK").unwrap(),
        );
        let b = r.bill(
            &Units::new().with(Unit::InputToken, 1_000_000),
            Currency::USD,
            &FxTable::default(),
        );
        assert!((b.source.amount - 10.0).abs() < 1e-9);
        assert_eq!(b.accounted, None);
        assert_eq!(b.amount(), 0.0);
        assert!(!b.is_known(), "an unconvertible charge is not a known one");
        assert_eq!(b.fx_rate, 1.0);
        // The ledger's unit does not depend on this row converting into it.
        assert_eq!(b.accounting, Currency::USD);
        // The source lines are denominated in SEK; filing them under USD would
        // report ten kronor as ten dollars.
        assert!(b.accounted_lines().is_empty());
        assert!(!b.source.lines.is_empty());
    }

    #[test]
    fn zeroing_a_charge_keeps_which_currencies_were_involved() {
        let fx: FxTable = serde_json::from_str(r#"{"EUR":{"USD":1.1}}"#).unwrap();
        let eur = Currency::parse("EUR").unwrap();
        let r = Rates::from_units(
            BTreeMap::from([(Unit::InputToken, Rate::Flat(10.0))]),
            eur,
        );
        let z = r
            .bill(
                &Units::new().with(Unit::InputToken, 1_000_000),
                Currency::USD,
                &fx,
            )
            .zeroed();
        assert_eq!(z.amount(), 0.0);
        assert_eq!(z.source.amount, 0.0);
        assert!(z.accounted_lines().is_empty());
        // Restating a euro-priced model as dollar-priced would misreport the row.
        assert_eq!(z.source.currency, eur);
        assert_eq!(z.accounting, Currency::USD);
        assert_eq!(z.fx_rate, 1.1);
    }

    #[test]
    fn free_traffic_stays_known_under_a_ledger_in_another_currency() {
        // A tenant keeping its books in euros, pricing its models in euros, has
        // no reason to configure a dollar pair. Bring-your-own-key and cache-hit
        // traffic must still read as free rather than unpriced — the badge means
        // "budgets over this will not enforce", which would be a lie about the
        // one category of request that is certainly free.
        let eur = Currency::parse("EUR").unwrap();
        let b = Rates::free().bill(
            &Units::new()
                .with(Unit::InputToken, 1_000)
                .with(Unit::OutputToken, 500),
            eur,
            &FxTable::default(),
        );
        assert!(b.is_known(), "free traffic must never be reported unpriced");
        assert_eq!(b.amount(), 0.0);
        assert_eq!(b.accounting, eur);
        // Nothing was charged in any currency, so claiming the provider quoted
        // dollars would be inventing a fact about a call nobody billed.
        assert_eq!(b.source.currency, eur);
        assert_eq!(b.fx_rate, 1.0);
    }

    #[test]
    fn billing_needs_no_conversion_when_the_currencies_agree() {
        let r = rates(&[(Unit::InputToken, 10.0)]);
        let b = r.bill(
            &Units::new().with(Unit::InputToken, 1_000_000),
            Currency::USD,
            &FxTable::default(),
        );
        assert_eq!(b.fx_rate, 1.0);
        assert!((b.amount() - 10.0).abs() < 1e-9);
        assert!(b.is_known());
    }

    #[test]
    fn an_unpriced_unit_survives_the_conversion() {
        let fx: FxTable = serde_json::from_str(r#"{"EUR":{"USD":1.1}}"#).unwrap();
        let r = Rates::from_units(
            BTreeMap::from([(Unit::InputToken, Rate::Flat(10.0))]),
            Currency::parse("EUR").unwrap(),
        );
        let b = r.bill(
            &Units::new()
                .with(Unit::InputToken, 1_000_000)
                .with(Unit::VideoSecond, 5),
            Currency::USD,
            &fx,
        );
        assert_eq!(b.accounted.as_ref().unwrap().unpriced, vec![Unit::VideoSecond]);
        assert!(!b.is_known());
    }

    #[test]
    fn an_unknown_rate_map_prices_nothing_and_says_so() {
        let cost = Rates::unknown().cost(&Units::new().with(Unit::InputToken, 1_000));
        assert_eq!(cost.amount, 0.0);
        assert_eq!(cost.unpriced, vec![Unit::InputToken]);
    }

    #[test]
    fn free_is_priced_at_zero_not_unknown() {
        let cost = Rates::free().cost(&Units::new().with(Unit::InputToken, 1_000_000));
        assert_eq!(cost.amount, 0.0);
        assert!(
            cost.is_known(),
            "bring-your-own-key traffic is free, not unpriced"
        );
    }

    #[test]
    fn a_zero_count_is_not_a_measurement() {
        let mut u = Units::new();
        u.add(Unit::InputToken, 0);
        assert!(u.is_empty());
        assert!(Rates::unknown().cost(&u).is_known());
    }

    #[test]
    fn tiers_apply_above_their_threshold_only() {
        let tiered = Rate::Tiered {
            rate: 1.25,
            tiers: vec![
                Tier { above: 128_000, rate: 2.50 },
                Tier { above: 1_000_000, rate: 5.00 },
            ],
        };
        assert_eq!(tiered.resolve(0), 1.25);
        assert_eq!(tiered.resolve(128_000), 1.25, "the threshold itself is below");
        assert_eq!(tiered.resolve(128_001), 2.50);
        assert_eq!(tiered.resolve(999_999), 2.50);
        assert_eq!(tiered.resolve(1_000_001), 5.00);
    }

    #[test]
    fn tiers_are_selected_by_the_raw_prompt_size() {
        // 200k prompt tokens of which 150k came from cache: the surcharge is on
        // what the provider had to hold in context, so the tier is chosen on the
        // full 200k even though only 50k is charged at the input rate.
        let r = Rates::from_units(
            BTreeMap::from([(
                Unit::InputToken,
                Rate::Tiered {
                    rate: 1.0,
                    tiers: vec![Tier { above: 128_000, rate: 2.0 }],
                },
            )]),
            Currency::USD,
        );
        let cost = r.cost(
            &Units::new()
                .with(Unit::InputToken, 200_000)
                .with(Unit::CacheReadToken, 150_000),
        );
        // 50k at 2.0 + 150k at 0.1x2.0.
        let expected = 0.05 * 2.0 + 0.15 * 0.2;
        assert!((cost.amount - expected).abs() < 1e-9, "{}", cost.amount);
    }

    #[test]
    fn tiers_out_of_order_still_pick_the_highest_matching() {
        let tiered = Rate::Tiered {
            rate: 1.0,
            tiers: vec![
                Tier { above: 1_000_000, rate: 5.0 },
                Tier { above: 128_000, rate: 2.0 },
            ],
        };
        assert_eq!(tiered.resolve(2_000_000), 5.0);
    }

    #[test]
    fn rates_round_trip_through_json() {
        let json = r#"{"currency":"EUR","units":{"input_token":0.2,"output_token":{"rate":0.6,"tiers":[{"above":128000,"rate":1.2}]}}}"#;
        let r: Rates = serde_json::from_str(json).unwrap();
        assert_eq!(r.currency, Currency::parse("EUR").unwrap());
        assert_eq!(r.units.get(&Unit::InputToken), Some(&Rate::Flat(0.2)));
        assert_eq!(
            r.units.get(&Unit::OutputToken).unwrap().resolve(200_000),
            1.2
        );
        let back = serde_json::to_string(&r).unwrap();
        let again: Rates = serde_json::from_str(&back).unwrap();
        assert_eq!(r, again);
    }

    #[test]
    fn an_empty_rate_map_deserializes_as_unknown_in_dollars() {
        let r: Rates = serde_json::from_str("{}").unwrap();
        assert_eq!(r, Rates::unknown());
        assert!(!r.zero_rated, "an absent price is unknown, not free");
    }

    #[test]
    fn a_unit_a_newer_admin_knows_is_dropped_not_fatal() {
        let json = r#"{"currency":"USD","units":{"input_token":1.0,"quantum_flux":9.0}}"#;
        let r: Rates = serde_json::from_str(json).unwrap();
        assert_eq!(r.units.len(), 1);
        assert_eq!(r.units.get(&Unit::InputToken), Some(&Rate::Flat(1.0)));
    }

    #[test]
    fn currency_parsing_rejects_what_it_cannot_name() {
        assert_eq!(Currency::parse("eur").unwrap().as_str(), "EUR");
        assert_eq!(Currency::parse(" usd ").unwrap(), Currency::USD);
        assert!(Currency::parse("EURO").is_none());
        assert!(Currency::parse("US").is_none());
        assert!(Currency::parse("U5D").is_none());
        assert!(Currency::parse("").is_none());
    }

    #[test]
    fn fx_converts_both_directions_from_one_configured_rate() {
        let fx: FxTable = serde_json::from_str(r#"{"EUR":{"USD":1.1}}"#).unwrap();
        let eur = Currency::parse("EUR").unwrap();
        assert_eq!(fx.convert(10.0, eur, Currency::USD), Some(11.0));
        let back = fx.convert(11.0, Currency::USD, eur).unwrap();
        assert!((back - 10.0).abs() < 1e-9, "{back}");
        assert_eq!(fx.convert(5.0, eur, eur), Some(5.0));
    }

    #[test]
    fn an_unconfigured_pair_is_not_converted_at_a_guess() {
        let fx: FxTable = serde_json::from_str(r#"{"EUR":{"USD":1.1}}"#).unwrap();
        let gbp = Currency::parse("GBP").unwrap();
        assert_eq!(fx.convert(10.0, gbp, Currency::USD), None);
        assert_eq!(FxTable::default().convert(10.0, gbp, Currency::USD), None);
    }

    #[test]
    fn a_nonsensical_fx_rate_is_refused() {
        let fx: FxTable = serde_json::from_str(r#"{"EUR":{"USD":0.0},"GBP":{"USD":-2.0}}"#).unwrap();
        assert_eq!(fx.convert(10.0, Currency::parse("EUR").unwrap(), Currency::USD), None);
        assert_eq!(fx.convert(10.0, Currency::parse("GBP").unwrap(), Currency::USD), None);
    }

    #[test]
    fn a_stored_breakdown_survives_a_unit_a_rolled_back_build_cannot_name() {
        // Written by a newer release, read after an A/B rollback. Erroring here
        // would fail the whole audit query and take every other row with it.
        let json = r#"{"input_token":{"count":10,"cost":1.0},
                       "quantum_flux":{"count":3,"cost":9.0}}"#;
        let mut de = serde_json::Deserializer::from_str(json);
        let parsed = deserialize_billed_units(&mut de).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[&Unit::InputToken].count, 10);
    }

    #[test]
    fn units_round_trip_through_json_by_wire_key() {
        let u = Units::new()
            .with(Unit::InputToken, 100)
            .with(Unit::CacheReadToken, 40);
        let json = serde_json::to_string(&u).unwrap();
        assert!(json.contains("\"input_token\":100"), "{json}");
        assert!(json.contains("\"cache_read_token\":40"), "{json}");
        assert_eq!(serde_json::from_str::<Units>(&json).unwrap(), u);
    }
}
