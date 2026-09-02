<?php

namespace App\Services\Network;

/**
 * Decides which DNS names this module is entitled to stay quiet about.
 *
 * **T-006320 asked for integration with "the existing DNS allowlist". There is
 * no existing DNS allowlist.** Verified before writing anything: no key
 * matching dns/domain allowlist exists in `storage/app/waf_config.json` (of the
 * 48 addon keys the Hub currently pushes, 24 are `edr_*`, and the three
 * allowlist-shaped ones among them are `edr_exclusions`,
 * `edr_web_account_allowlist` and `edr_isolation_allowlist`, none of which is
 * about domains), and nothing in the app tree matches
 * `(dns|domain).*allow|allow.*(dns|domain)`. `EdrRuleEngine::setExclusions()`
 * matches a regex against the executable path joined to the command line, which
 * a DNS event does not have (Suricata sees packets, so `DnsEventNormalizer`
 * fills path and cmdline with empty strings by design), so reusing it would
 * produce an allowlist that silently matches nothing. This class is therefore
 * the first one, and the task's assumption is recorded here so the next reader
 * does not go looking for the one it thought existed.
 *
 * Everything numeric below was measured on this host's own DNS telemetry:
 * 23,234 `event_type":"dns"` rows carrying an rrname from
 * /var/log/suricata/eve.json, 23:05:29 to 23:52:57 on 28 August 2026, 42
 * distinct names. The corpus limit is the one `DnsEventNormalizer` documents:
 * the seven rotated generations hold 0 dns rows, so this window is the whole
 * DNS corpus that exists on this host. The module brief's larger 40k-event
 * sample counted ~360 distinct domains; where the two disagree the wider sample
 * is quoted as well.
 *
 * WHAT SUFFIX MATCHING HAS TO GET RIGHT, AND WHY THE REAL DATA CANNOT PROVE IT
 *
 * An entry for `example.com` must match `example.com` and `api.example.com`,
 * and must not match `notexample.com` or `example.com.evil.net`. Substring
 * matching gets the last two wrong, and the second of them is a live bypass: an
 * attacker who can read the allowlist registers `example.com.evil.net`, which a
 * substring matcher excuses and whose authoritative server the attacker owns.
 *
 * Measured: on this host, the naive matcher and the correct one agree on every
 * row. Of the 42 distinct queried names there are 0 pairs where one name
 * contains another as a non-suffix substring, so substring matching would have
 * produced identical output on all 23,234 rows. That is the argument for proving
 * this against synthetic names in the test rather than against the stream: the
 * bug is invisible in this host's traffic and stays invisible right up to the
 * point where it is used. Matching here is done by slicing labels, never by
 * string position, so the boundary is structural.
 *
 * INTERNAL NAMES ARE RECOGNISED, NOT CONFIGURED
 *
 * A set of reserved suffixes is auto-recognised (see
 * RESERVED_INTERNAL_SUFFIXES) plus every dotless name. The justification is one
 * property rather than a convention: no third party can obtain a delegation
 * under any of them, so the far end of a query for a name under one of them
 * cannot be an authoritative server an attacker chose. DNS tunnelling and DNS
 * exfiltration both need exactly that, so a name under these suffixes is not a
 * candidate carrier, whatever it looks like. Dotless names have the same
 * property from the other direction: ICANN prohibits address records at a TLD
 * apex and no registry sells a dotless name, so `nginx-proxy` resolves through
 * the search list or not at all.
 *
 * Measured, this is not a blanket. Running this class over the corpus, the
 * auto-recognised set excuses 510 of 23,234 rows (2.20%): 362 under
 * `.internal`, all of them host.docker.internal; 20 under `.invalid` (16
 * no-such-host-abc123xyz.invalid and 4 for the bare label `invalid`, which the
 * reserved exact match claims before the dotless rule sees it); and 128 dotless,
 * all nginx-proxy. Zero rows fell under .local, .lan, .localdomain, .home.arpa,
 * .localhost, .test or .example, so most of the set fires on nothing here and is
 * present because the next host is a container host or a corporate LAN, not
 * because it was needed.
 *
 * Measured, it is also the difference between a usable NXDOMAIN rule and a rule
 * made of container noise: all 255 NXDOMAIN rows in the corpus are either
 * dotless or under a reserved suffix (host.docker.internal 181, nginx-proxy 64,
 * no-such-host-abc123xyz.invalid 8, invalid 2). An NXDOMAIN-rate detector built
 * without this classification would be measuring Docker's resolver behaviour
 * and nothing else, which is also what the 3.35% NXDOMAIN baseline in the
 * module brief is made of.
 *
 * Two kinds of name that belong to no ordinary delegation are deliberately NOT
 * in the set:
 *
 * `.onion` (RFC 7686) is non-delegatable and would qualify on the argument
 * above, but a .onion name reaching a public resolver is itself the finding: it
 * means something on this host tried to resolve a hidden service without Tor.
 * Excusing it would delete a signal, not noise.
 *
 * `in-addr.arpa` and `ip6.arpa` are the one place the delegation argument
 * fails: reverse zones ARE delegated in the public DNS, to whoever holds the
 * address block, and an ip6.arpa name carries 32 attacker-chosen nibbles per
 * query. Measured 0 of 23,234 rows, so leaving them out costs this host
 * nothing, and a host that does heavy PTR resolution can allowlist the specific
 * reverse zone it queries.
 *
 * DISCOVERY READS WHAT THIS HOST CONFIGURED, NEVER WHAT AN ANSWER SAID
 *
 * `discoverInternalDomains()` reads the resolver search list and the kernel
 * hostname. It deliberately does not learn from answers, and that is a security
 * decision rather than an omission: the obvious heuristic ("a name that only
 * ever resolves into RFC 1918 space is internal infrastructure") is decided by
 * whoever operates the zone, so an attacker publishes one A record in private
 * space and their own C2 domain is auto-allowlisted. DNS rebinding is that
 * primitive already, and it costs an attacker one record. Discovery therefore
 * only reads sources this host controls.
 *
 * A discovered suffix is applied only when it is itself non-delegatable. A
 * search domain that is a public zone (a real shape: `search corp.example.com`)
 * is returned as a candidate for a human to approve, because names under a
 * public zone can be created by anyone who can create records in it, and
 * silently allowlisting the whole zone deletes the tunnelling detection for the
 * one zone an insider can write to.
 *
 * Measured on this host discovery returns nothing at all: /etc/resolv.conf is
 * the systemd-resolved file and its search line is `search .`, which is
 * systemd's way of writing "no search domain", and `hostname` is `gx10-dc8a`
 * with no domain part. So it reports the basis it had rather than an empty
 * array, and this host's internal recognition rests entirely on the reserved
 * set. A discovery mechanism that returns zero on the host it was written on is
 * exactly the mechanism that would otherwise have been assumed to work.
 *
 * AN ALLOWLIST MUST NOT BE ABLE TO HIDE EVERYTHING, AND VOLUME CANNOT BE THE TEST
 *
 * Measured suppression, as a fraction of the 23,234 rows:
 *   `*` or `.`                      100%
 *   `com`                            93.96%  (30 of the 42 distinct names)
 *   `cybersecureone.com`             46.86%  (6 distinct names)
 *   `github.com`                     35.90%  (2 distinct names)
 *   the reserved set and dotless      2.20%
 *
 * The second and third lines are why over-breadth is refused structurally and
 * reported volumetrically, rather than the other way round. `cybersecureone.com`
 * is this product's own control plane, and `DnsEventNormalizer` documents that
 * a rarity rule has to be told about the agent's own destinations by domain
 * because there is no process name to filter on. It is the single most
 * defensible entry anybody will ever add here, and it covers nearly half the
 * stream. Any percentage ceiling low enough to refuse `com` at 93.96% and high
 * enough to keep that entry has no margin, and the same entry on a quieter host
 * covers 0%: coverage is a property of the sample, not of the entry, and the
 * allowlist is installed before a single event has been seen. So:
 *
 * - Refused, at configuration time, on shape alone: anything matching
 *   everything (`*`, `.`), a wildcard anywhere but a leading `*.`, a bare TLD
 *   (one label), a suffix under which third parties can obtain a name
 *   (REGISTRY_SUFFIXES), a name with a label that is not a DNS label at all
 *   (over-long, empty, or outside a-z 0-9 hyphen underscore after
 *   normalisation), and anything past MAX_ENTRIES. Underscore is inside that
 *   set deliberately, not by oversight: _dmarc and _acme-challenge are names an
 *   operator has real reason to allowlist. Non-ASCII is converted to punycode
 *   rather than refused, so an entry written in the operator's own script
 *   matches the name that goes on the wire.
 * - Reported, once traffic exists: `coverage()` gives per-entry row and
 *   distinct-name counts and flags both failure modes named in
 *   EdrExclusionSuggester's docblock, an entry that matches nothing and an entry
 *   that matches nearly everything.
 *
 * What is deliberately not prevented: an operator adding all 42 domains one at a
 * time, which would suppress 100% of this stream. Each of those entries is
 * defensible on its own, the aggregate is not, and the only honest place to see
 * that is the total in the coverage report. It is reported as
 * `suppressed_fraction` for that reason.
 *
 * REFUSAL IS VISIBLE, BECAUSE A STORED ENTRY THAT CANNOT MATCH READS AS APPLIED
 *
 * This is the failure that has already happened once in this codebase.
 * `EdrExclusionSuggester` emitted exclusions anchored to the wrong end of the
 * haystack; `setExclusions()` accepted them because the regex compiled, the Hub
 * showed them as applied, and the only symptom was that the noisy rule kept
 * firing. So nothing here is stored unless it can match: a refused entry is
 * never added to the table, and `refused()` returns every one with a reason and
 * a message intended for the operator who approved it. The caller is expected to
 * report that alongside the heartbeat. Silence would recreate the same bug with
 * a different field.
 *
 * WHAT THE TWO SUPPRESSING VERDICTS ENTITLE A CALLER TO DO
 *
 * `classify()` returns 'allowed', 'internal' or 'evaluate', and there is
 * deliberately no `suppresses(): bool` helper, because the two suppressing
 * verdicts do not license the same thing:
 *
 * - 'internal' says the name cannot be the far end of a data channel. It
 *   excuses the domain-identity rules (tunnelling, exfiltration, DGA, rare or
 *   never-before-seen domain, NXDOMAIN rate). It must NOT excuse the volumetric
 *   and timing rules: a beacon to an internal resolver is still a beacon.
 * - 'allowed' says an operator accepted this domain. It excuses the same
 *   domain-identity rules, and an entry may carry `rules` to narrow that to
 *   named rules only, the way an EdrRuleEngine exclusion carries a user.
 *
 * A structurally anomalous name overrides both. If the normaliser flagged the
 * name with any of ANOMALY_FLAGS the verdict is 'evaluate' even when an entry
 * matched, and the entry that was overridden is reported. The reason is that an
 * allowlist entry is a suffix, and a suffix says nothing about the labels to its
 * left, which is where a tunnel puts its payload. Measured, this override fires
 * on nothing real: 0 of 23,234 rows carried any flag except single_label, which
 * is the internal marker itself and is not in the anomaly set.
 *
 * @see DnsEventNormalizer for the event shape, the domain_flags vocabulary and
 *      the corpus limit.
 * @see EdrRuleEngine::setExclusions() for the string-or-array entry shape and
 *      the scoped-suppression precedent.
 */
class DnsAllowlist
{
    /**
     * The Hub keys this expects, following the existing `edr_*` addons.
     *
     * WafSyncService is not edited by this task, so the key names are declared
     * here and the mapping it needs is stated in full. In
     * `WafSyncService::edrSensorOptions()`:
     *
     *   'dns_allowlist' => is_array($addons['edr_dns_allowlist'] ?? null)
     *       ? $addons['edr_dns_allowlist'] : [],
     *   'dns_internal_domains' => is_array($addons['edr_dns_internal_domains'] ?? null)
     *       ? $addons['edr_dns_internal_domains'] : [],
     *   'dns_internal_discovery' => (bool) ($addons['edr_dns_internal_discovery'] ?? true),
     *
     * `edr_dns_allowlist` holds either bare strings or
     * `{suffix|domain, rules?, note?}` objects. `edr_dns_internal_domains` adds
     * site-specific internal suffixes and holds bare strings only: an internal
     * suffix is a statement about the namespace, so scoping it to one rule would
     * be meaningless. Discovery defaults on because its only effect is to apply
     * non-delegatable suffixes this host already resolves through.
     */
    public const HUB_ALLOWLIST_KEY = 'edr_dns_allowlist';
    public const HUB_INTERNAL_KEY = 'edr_dns_internal_domains';
    public const HUB_DISCOVERY_KEY = 'edr_dns_internal_discovery';

    /**
     * Suffixes under which no third party can obtain a delegation.
     *
     * Not Hub-tunable, and the Hub cannot remove one: this is a property of the
     * DNS namespace rather than of this deployment, so a per-host override would
     * be a way to lose the property without noticing. The Hub adds to it through
     * HUB_INTERNAL_KEY.
     *
     * Sources, so a future reader can check rather than trust: RFC 6761
     * (localhost, invalid, example, test), RFC 6762 (local), RFC 8375
     * (home.arpa), and the ICANN Board's 2024 reservation of `internal` for
     * private use. `lan` and `localdomain` are reserved by nobody; they are here
     * because they are not TLDs and cannot be registered, which is the property
     * this set is actually about, and because they are the defaults baked into
     * consumer routers and into glibc/dhclient respectively.
     *
     * Measured coverage on this host: 382 of 23,234 rows, from `.internal` (362)
     * and `.invalid` (20). The other seven fired on nothing.
     */
    public const RESERVED_INTERNAL_SUFFIXES = [
        'internal',
        'local',
        'localdomain',
        'lan',
        'home.arpa',
        'localhost',
        'invalid',
        'test',
        'example',
    ];

    /**
     * Suffixes refused as entries because a third party can obtain a name under
     * them.
     *
     * An entry is a suffix, so allowlisting one of these allowlists strangers.
     * `dyndns.org` is not hypothetical here: this host really does query
     * gpg-gtb.dyndns.org, 54 rows in the corpus, so an operator tuning that
     * noise would plausibly write the parent, and dynamic-DNS parents are what
     * commodity C2 resolves under. `cloudapp.azure.com` is in the corpus too, as
     * a CNAME target of mobile.events.data.microsoft.com. Both would have been
     * added by somebody, eventually, for a good local reason.
     *
     * **This is not a public suffix list and must not be read as one.** There is
     * no PSL in this project (checked: nothing in composer.json or the vendor
     * tree provides one) and shipping a copy would mean shipping a file that
     * goes stale inside a vendor directory that cannot be updated on this host.
     * So this is a refusal list of the suffixes that actually turn up in tuning
     * requests and in C2, it is incomplete by construction, and the compensating
     * control for what it misses is `coverage()`, where an entry one label above
     * a registry boundary shows up as covering an implausible share of the
     * stream or an implausible number of distinct names.
     *
     * A refusal here is never a loss of visibility. The operator names the host
     * instead of the parent (`myapp.herokuapp.com`, not `herokuapp.com`), which
     * is the entry they meant.
     */
    public const REGISTRY_SUFFIXES = [
        // Country-code second levels, .tw first because this is a Taiwanese
        // deployment and sp.spx.shopee.tw is in the corpus.
        'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw',
        'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk',
        'co.jp', 'ne.jp', 'or.jp', 'ac.jp',
        'com.cn', 'net.cn', 'org.cn',
        'com.hk', 'com.sg', 'com.my', 'co.th', 'com.ph', 'com.vn',
        'co.in', 'co.kr', 'or.kr',
        'com.au', 'net.au', 'org.au', 'com.br', 'com.mx', 'com.ar',
        'co.nz', 'co.za', 'com.tr', 'co.il', 'com.ua', 'com.pl',
        // Dynamic DNS.
        'dyndns.org', 'ddns.net', 'no-ip.org', 'no-ip.com', 'hopto.org',
        'zapto.org', 'sytes.net', 'myftp.org', 'redirectme.net', 'duckdns.org',
        'mooo.com', 'chickenkiller.com',
        // Tunnels, which is how a payload gets a working name in minutes.
        'ngrok.io', 'ngrok.app', 'ngrok-free.app', 'trycloudflare.com',
        'loca.lt', 'localhost.run', 'pagekite.me', 'telebit.io',
        // Anyone-can-deploy hosting and object storage.
        'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'r2.dev',
        'vercel.app', 'netlify.app', 'herokuapp.com', 'appspot.com',
        'web.app', 'firebaseapp.com', 'onrender.com', 'fly.dev', 'koyeb.app',
        'glitch.me', 'repl.co', 'replit.dev',
        'azurewebsites.net', 'cloudapp.azure.com', 'blob.core.windows.net',
        'cloudfront.net', 'amazonaws.com', 's3.amazonaws.com',
        'googleusercontent.com', 'storage.googleapis.com',
        'digitaloceanspaces.com', 'sharepoint.com',
        'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com',
    ];

    /**
     * Domain flags that override a match, from DnsEventNormalizer's vocabulary.
     *
     * The four shapes here are the ones with the capacity to carry data or the
     * character set to encode it, which is what an allowlisted suffix cannot
     * speak for. `single_label` is excluded because it IS the dotless internal
     * marker, and `hyphen_edge` is excluded because a leading or trailing hyphen
     * is malformedness rather than capacity, and overriding on it would mean an
     * allowlist that stops working on a typo.
     *
     * Measured: 0 of 23,234 rows carried any of these four, so the override
     * costs nothing on real traffic and anything it fires on is new.
     */
    public const ANOMALY_FLAGS = [
        'name_too_long',
        'label_too_long',
        'empty_label',
        'non_ldh_character',
    ];

    /**
     * Presentation-form limits, RFC 1035 2.3.4 and 3.1, the same values
     * DnsEventNormalizer uses.
     *
     * The normaliser FLAGS an over-long name because a long name in many labels
     * is the tunnelling carrier and dropping it would delete the evidence. An
     * over-long allowlist ENTRY is refused, and the asymmetry is deliberate:
     * every name under an over-long suffix is also over-long, so the entry could
     * only ever suppress protocol-violating names, which is the one thing an
     * allowlist must not be able to do. This is the single refusal that refuses
     * a suppression rather than an error, and it fails towards detection.
     */
    private const MAX_NAME_LENGTH = 253;
    private const MAX_LABEL_LENGTH = 63;

    /**
     * Ceiling on applied entries, with the overflow refused rather than
     * truncated.
     *
     * Not a performance limit. Matching walks the queried name's label
     * boundaries and does a hash lookup at each, so its cost is bounded by label
     * depth and by the deepest configured entry, never by how many entries there
     * are. The ceiling is there so a corrupted or hostile config push cannot
     * turn a sync into unbounded memory, and 500 is roughly 12 times the 42
     * distinct names this host resolved in 47 minutes and around 1.4 times the
     * ~360 distinct domains the module brief measured over a 40k-event sample.
     * An allowlist larger than every domain the host has ever queried is not a
     * tuning list.
     */
    private const MAX_ENTRIES = 500;

    /**
     * Coverage above which an entry is flagged as dominant in the report.
     *
     * Between the two measured poles and clear of both: the broadest legitimate
     * entry on this host covers 46.86% (cybersecureone.com, the agent's own
     * control plane) and the narrowest structurally over-broad one covers 93.96%
     * (`com`, which is refused before it can ever be measured). This is a report
     * flag and never a refusal, so a genuinely single-purpose host that exceeds
     * it gets a note rather than a lost entry.
     */
    private const DOMINANT_FRACTION = 0.75;

    /** @var array<string, array{suffix: string, rules: ?array<int, string>, note: ?string}> */
    private array $allowed = [];

    /** @var array<string, array{suffix: string, source: string}> */
    private array $internal = [];

    /**
     * Refusals and notes are kept per source, so one setter cannot clear
     * another's findings and a per-cycle re-push cannot make them accumulate.
     * `setAllowlist()` runs every sync; discovery runs on its own schedule.
     *
     * @var array<string, array<int, array<string, string>>>
     */
    private array $refused = ['allowlist' => [], 'internal' => [], 'discovery' => []];

    /** @var array<string, array<int, array<string, string>>> */
    private array $notes = ['allowlist' => [], 'internal' => [], 'discovery' => []];

    /** Which bucket the parser is currently writing into. */
    private string $bucket = 'allowlist';

    /** @var array<string, string> suffix => source, Hub-supplied internal suffixes */
    private array $internalFromHub = [];

    /** @var array<string, string> suffix => source, discovered internal suffixes */
    private array $internalDiscovered = [];

    /** Deepest entry in each table, in labels, so the match walk is bounded. */
    private int $allowedDepth = 0;
    private int $internalDepth = 0;

    public function __construct()
    {
        $this->rebuildInternal();
    }

    /**
     * Install the operator allowlist, replacing whatever was there.
     *
     * Replaces rather than merges, for the reason `setExclusions()` does: the
     * Hub pushes the whole list every sync, so merging would mean a removal
     * never takes effect.
     *
     * @param array<int|string, mixed> $entries bare suffixes, or
     *        {suffix|domain, rules?, note?} objects
     */
    public function setAllowlist(array $entries): void
    {
        $this->bucket = 'allowlist';
        $this->allowed = [];
        $this->refused['allowlist'] = [];
        $this->notes['allowlist'] = [];
        $this->allowedDepth = 0;

        foreach ($entries as $raw) {
            if (count($this->allowed) >= self::MAX_ENTRIES) {
                $this->refuse(
                    $this->describe($raw),
                    'entry_limit',
                    'not applied: the allowlist is capped at ' . self::MAX_ENTRIES
                    . ' entries and this one is past the cap'
                );
                continue;
            }

            $parsed = $this->parseEntry($raw);

            if ($parsed === null) {
                continue;
            }

            $suffix = $parsed['suffix'];

            if (isset($this->allowed[$suffix])) {
                $this->note($suffix, 'duplicate', 'the same suffix appears more than once; the first is kept');
                continue;
            }

            // The one way an entry can be inert that is visible without traffic:
            // the whole suffix is already excused by the internal
            // classification, which no config can remove.
            $reserved = $this->matchIn($suffix, $this->internal, $this->internalDepth, null, true);

            if ($reserved !== null) {
                $this->note(
                    $suffix,
                    'redundant_with_internal',
                    'already recognised as internal through ' . $reserved['suffix']
                    . ' (' . $reserved['source'] . '), so this entry changes nothing'
                );
            }

            $this->allowed[$suffix] = [
                'suffix' => $suffix,
                'rules' => $parsed['rules'],
                'note' => $parsed['note'],
            ];
            $this->allowedDepth = max($this->allowedDepth, $this->depth($suffix));
        }

        $this->noteShadowedEntries();
    }

    /**
     * Flag every entry that sits under a broader entry in the same list.
     *
     * A separate pass rather than a check inside the loop, because inside the
     * loop it is order-dependent: `['github.com', 'api.github.com']` would be
     * flagged and `['api.github.com', 'github.com']` would not, which makes the
     * report depend on the order the Hub happened to serialise the list in.
     *
     * A shadowed entry is applied, not refused. Its effect is already covered,
     * so nothing is lost, but an operator reading the list would credit it with
     * a scope it does not have, which is the same class of mistake as an
     * exclusion that matches nothing.
     */
    private function noteShadowedEntries(): void
    {
        foreach (array_keys($this->allowed) as $suffix) {
            $labels = explode('.', $suffix);
            $count = count($labels);

            for ($i = 1; $i < $count; $i++) {
                $parent = implode('.', array_slice($labels, $i));

                if (isset($this->allowed[$parent])) {
                    $this->note(
                        $suffix,
                        'shadowed',
                        'already covered by the broader entry ' . $parent . ', so this narrows nothing'
                    );
                    break;
                }
            }
        }
    }

    /**
     * Add site-specific internal suffixes from the Hub.
     *
     * These are trusted to be internal because a human said so, so unlike
     * discovery they are applied even when the suffix is publicly delegatable (a
     * corporate zone under a public domain is the normal case). They still go
     * through the same shape refusals, REGISTRY_SUFFIXES included: naming a
     * dynamic-DNS parent as an internal domain is the same mistake through a
     * different key.
     *
     * @param array<int, mixed> $suffixes
     */
    public function setInternalDomains(array $suffixes): void
    {
        $this->bucket = 'internal';
        $this->refused['internal'] = [];
        $this->notes['internal'] = [];
        $this->internalFromHub = [];

        foreach ($suffixes as $raw) {
            $parsed = $this->parseEntry($raw, false);

            if ($parsed === null) {
                continue;
            }

            $this->internalFromHub[$parsed['suffix']] = 'hub';
        }

        $this->rebuildInternal();
    }

    /**
     * Discover internal suffixes from what this host is configured with.
     *
     * Reads the resolver search list and the kernel hostname, both of which this
     * host owns. Answers are deliberately not a source: see the class docblock
     * on rebinding.
     *
     * Non-delegatable results are applied. Publicly delegatable ones are
     * returned as candidates and NOT applied, because allowlisting a whole
     * public zone is a decision with a blast radius and this class does not get
     * to make it.
     *
     * The `basis` key distinguishes "we looked and this host has no search
     * domain" from "we could not look", because on this host the answer is the
     * former and an empty array cannot say which. Measured: /etc/resolv.conf
     * here is systemd-resolved's file, its search line is the bare `.` that
     * systemd writes when there is no search domain, and the hostname
     * (gx10-dc8a) has no domain part, so this returns nothing on the host it was
     * written on.
     *
     * @param string $resolvConf path, parameterised for the test rather than for
     *        configuration
     * @return array{applied: array<int, string>, candidates: array<int, string>, basis: string}
     */
    public function discoverInternalDomains(string $resolvConf = '/etc/resolv.conf'): array
    {
        $this->bucket = 'discovery';
        $this->refused['discovery'] = [];
        $this->notes['discovery'] = [];
        $this->internalDiscovered = [];

        $applied = [];
        $candidates = [];
        $sources = [];

        $lines = is_readable($resolvConf)
            ? @file($resolvConf, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)
            : false;

        if ($lines === false) {
            // Not the same finding as "there are none". A container with no
            // resolv.conf mounted and a host with an empty search list look
            // identical from the return value alone, and one of them means this
            // host's internal names are invisible to us.
            $this->rebuildInternal();

            return ['applied' => [], 'candidates' => [], 'basis' => 'unreadable:' . $resolvConf];
        }

        foreach ($lines as $line) {
            $line = trim($line);

            if ($line === '' || $line[0] === '#' || $line[0] === ';') {
                continue;
            }

            $parts = preg_split('/\s+/', $line) ?: [];
            $directive = strtolower((string) array_shift($parts));

            // `domain` is the single-value form and `search` the list form. Both
            // are read because a hand-written static resolv.conf still uses
            // `domain`.
            if ($directive !== 'search' && $directive !== 'domain') {
                continue;
            }

            foreach ($parts as $candidate) {
                // systemd-resolved writes `search .` for "no search domain", and
                // a leading `~` is its routing-only marker. Either would
                // otherwise become a suffix that matches every name there is.
                $candidate = ltrim($candidate, '~');

                if ($candidate === '' || $candidate === '.') {
                    continue;
                }

                $sources[] = $candidate;
            }
        }

        $hostname = (string) gethostname();

        // Only useful when the kernel hostname is an FQDN, which it is not here.
        // Taken from the string rather than from a resolver call on purpose: a
        // discovery step that resolved anything would add queries to the stream
        // this module measures.
        if (str_contains($hostname, '.')) {
            $sources[] = substr($hostname, strpos($hostname, '.') + 1);
        }

        foreach ($sources as $candidate) {
            $parsed = $this->parseEntry($candidate, false);

            if ($parsed === null) {
                continue;
            }

            $suffix = $parsed['suffix'];

            if ($this->isNonDelegatable($suffix)) {
                $this->internalDiscovered[$suffix] = 'discovered';
                $applied[] = $suffix;
                continue;
            }

            $candidates[] = $suffix;
        }

        $this->rebuildInternal();

        return [
            'applied' => array_values(array_unique($applied)),
            'candidates' => array_values(array_unique($candidates)),
            'basis' => $sources === [] ? 'no_search_domain' : 'search_domain',
        ];
    }

    /**
     * Classify one normalised DNS event.
     *
     * Takes the event rather than the name so the domain flags cannot be left
     * behind: the anomaly override is the only thing standing between an
     * allowlisted suffix and a tunnel underneath it, and a caller that had to
     * remember to pass the flags separately would eventually not.
     * `classifyName()` exists for callers that genuinely have only a name, and it
     * makes the flags a required argument for the same reason.
     *
     * @param array $event a DnsEventNormalizer event
     * @param string|null $rule the rule asking, so rule-scoped entries can be
     *        honoured. Null means "no rule named", and a rule-scoped entry then
     *        does not apply, which fails towards detection.
     * @return array{verdict: string, reason: string, name: string, entry: ?string, source: ?string}
     */
    public function classify(array $event, ?string $rule = null): array
    {
        $dns = is_array($event['dns'] ?? null) ? $event['dns'] : null;

        if ($dns === null) {
            return $this->verdict('evaluate', 'no_dns_section', '');
        }

        $flags = is_array($dns['domain_flags'] ?? null) ? $dns['domain_flags'] : [];

        return $this->classifyName((string) ($dns['rrname'] ?? ''), $flags, $rule);
    }

    /**
     * @param array<int, string> $domainFlags DnsEventNormalizer's
     *        dns.domain_flags. Required rather than defaulted, so it cannot be
     *        forgotten.
     * @return array{verdict: string, reason: string, name: string, entry: ?string, source: ?string}
     */
    public function classifyName(string $rrname, array $domainFlags, ?string $rule = null): array
    {
        // Normalised the way DnsEventNormalizer normalises an rrname, so the two
        // agree on what the name is. A caller passing a raw name with a trailing
        // dot or a capital letter would otherwise miss every entry.
        $name = strtolower(rtrim(trim($rrname), '.'));

        if ($name === '') {
            // Never suppress on a name we cannot read.
            return $this->verdict('evaluate', 'no_name', '');
        }

        $anomalous = array_values(array_intersect($domainFlags, self::ANOMALY_FLAGS));

        // Internal is checked before the operator list on purpose. Where both
        // would match, the internal classification is the honest reason: it is
        // automatic, no config push can remove it, and reporting the operator's
        // entry instead would credit an entry that is doing no work.
        $internal = $this->matchIn($name, $this->internal, $this->internalDepth, null, true);

        if ($internal === null && $this->depth($name) === 1) {
            $internal = ['suffix' => $name, 'source' => 'dotless'];
        }

        if ($internal !== null) {
            if ($anomalous !== []) {
                return $this->verdict(
                    'evaluate',
                    'anomalous_under_internal:' . implode(',', $anomalous),
                    $name,
                    $internal['suffix'],
                    $internal['source']
                );
            }

            return $this->verdict(
                'internal',
                $internal['source'] === 'dotless' ? 'dotless' : 'internal_suffix',
                $name,
                $internal['suffix'],
                $internal['source']
            );
        }

        $entry = $this->matchIn($name, $this->allowed, $this->allowedDepth, $rule);

        if ($entry === null) {
            return $this->verdict('evaluate', 'no_match', $name);
        }

        if ($anomalous !== []) {
            return $this->verdict(
                'evaluate',
                'anomalous_under_allowlist:' . implode(',', $anomalous),
                $name,
                $entry['suffix'],
                'hub'
            );
        }

        return $this->verdict('allowed', 'allowlisted', $name, $entry['suffix'], 'hub');
    }

    /**
     * What this allowlist would actually suppress, measured on a sample.
     *
     * Takes names already read from somewhere else, never a log path: there is
     * one cursor over eve.json and it is not this class's (see
     * DnsEventNormalizer on why a second one turns "why did DNS miss this" into
     * a question about which cursor was where).
     *
     * Both of EdrExclusionSuggester's failure modes are reported, because an
     * entry that silently matches nothing and an entry that silently matches
     * everything are equally invisible from the config alone: `matches_nothing`,
     * `dominant`, and the redundancy notes from install time.
     *
     * Two things this report deliberately does differently from a live verdict,
     * both because a sample of names carries neither flags nor a rule:
     * the anomaly override cannot apply, and rule scope is ignored, so a
     * rule-scoped entry is credited with everything it covers and flagged
     * `rule_scoped`. Counting a scoped entry's reach as zero would report the
     * one failure mode this method exists to catch, against an entry that is
     * working exactly as approved.
     *
     * `basis` is false for an empty sample, so "nothing was suppressed" cannot
     * be read off a report that had nothing to look at.
     *
     * @param array<int|string, mixed> $names a list of rrnames, or a map of
     *        rrname => row count
     * @return array{basis: bool, rows: int, distinct: int, suppressed_rows: int,
     *         suppressed_fraction: float, internal_rows: int, allowed_rows: int,
     *         evaluated_rows: int, entries: array<string, array>,
     *         internal: array<string, array>}
     */
    public function coverage(array $names): array
    {
        $counts = [];

        foreach ($names as $key => $value) {
            if (is_string($key)) {
                $counts[$key] = ($counts[$key] ?? 0) + (int) $value;
                continue;
            }

            if (is_string($value) && $value !== '') {
                $counts[$value] = ($counts[$value] ?? 0) + 1;
            }
        }

        $report = [
            'basis' => $counts !== [],
            'rows' => array_sum($counts),
            'distinct' => count($counts),
            'suppressed_rows' => 0,
            'suppressed_fraction' => 0.0,
            'internal_rows' => 0,
            'allowed_rows' => 0,
            'evaluated_rows' => 0,
            'entries' => [],
            'internal' => [],
        ];

        foreach (array_keys($this->allowed) as $suffix) {
            $report['entries'][$suffix] = ['rows' => 0, 'distinct' => 0, 'fraction' => 0.0, 'flags' => []];
        }

        foreach (array_keys($this->internal) as $suffix) {
            $report['internal'][$suffix] = ['rows' => 0, 'distinct' => 0, 'fraction' => 0.0];
        }

        $report['internal']['(dotless)'] = ['rows' => 0, 'distinct' => 0, 'fraction' => 0.0];

        foreach ($counts as $name => $rows) {
            $name = strtolower(rtrim(trim((string) $name), '.'));

            if ($name === '') {
                $report['evaluated_rows'] += $rows;
                continue;
            }

            $internal = $this->matchIn($name, $this->internal, $this->internalDepth, null, true);
            $key = $internal['suffix'] ?? null;

            if ($internal === null && $this->depth($name) === 1) {
                $key = '(dotless)';
            }

            if ($key !== null) {
                $report['internal'][$key]['rows'] += $rows;
                $report['internal'][$key]['distinct']++;
                $report['internal_rows'] += $rows;
                continue;
            }

            // Scope ignored on purpose: see the docblock.
            $entry = $this->matchIn($name, $this->allowed, $this->allowedDepth, null, true);

            if ($entry === null) {
                $report['evaluated_rows'] += $rows;
                continue;
            }

            $report['entries'][$entry['suffix']]['rows'] += $rows;
            $report['entries'][$entry['suffix']]['distinct']++;
            $report['allowed_rows'] += $rows;
        }

        $report['suppressed_rows'] = $report['internal_rows'] + $report['allowed_rows'];
        $total = max(1, $report['rows']);
        $report['suppressed_fraction'] = round($report['suppressed_rows'] / $total, 4);

        foreach ($report['entries'] as $suffix => $stats) {
            $fraction = round($stats['rows'] / $total, 4);
            $flags = [];

            if ($stats['rows'] === 0 && $report['basis']) {
                // The EdrExclusionSuggester failure: approved, stored, inert.
                // Only reportable with a sample, which is why refusal at install
                // time cannot be the only control.
                $flags[] = 'matches_nothing';
            }

            if ($fraction >= self::DOMINANT_FRACTION) {
                $flags[] = 'dominant';
            }

            if (($this->allowed[$suffix]['rules'] ?? null) !== null) {
                $flags[] = 'rule_scoped';
            }

            foreach ($this->notes['allowlist'] as $note) {
                if ($note['entry'] === $suffix) {
                    $flags[] = $note['note'];
                }
            }

            $report['entries'][$suffix]['fraction'] = $fraction;
            $report['entries'][$suffix]['flags'] = array_values(array_unique($flags));
        }

        foreach ($report['internal'] as $suffix => $stats) {
            $report['internal'][$suffix]['fraction'] = round($stats['rows'] / $total, 4);
        }

        return $report;
    }

    /**
     * Entries that were not stored, with a reason and a message for whoever
     * approved them.
     *
     * @param string|null $source 'allowlist', 'internal' or 'discovery'; all
     *        three when null
     * @return array<int, array<string, string>>
     */
    public function refused(?string $source = null): array
    {
        if ($source !== null) {
            return $this->refused[$source] ?? [];
        }

        return array_merge(...array_values($this->refused));
    }

    /**
     * Entries that were stored but do nothing useful: duplicated, shadowed by a
     * broader entry, already covered by the internal classification, or with a
     * wildcard read back to a plain suffix.
     *
     * @return array<int, array<string, string>>
     */
    public function notes(?string $source = null): array
    {
        if ($source !== null) {
            return $this->notes[$source] ?? [];
        }

        return array_merge(...array_values($this->notes));
    }

    /** @return array<int, string> the applied allowlist suffixes */
    public function entries(): array
    {
        return array_keys($this->allowed);
    }

    /** @return array<string, string> suffix => source for every internal suffix */
    public function internalSuffixes(): array
    {
        return array_map(static fn (array $row): string => $row['source'], $this->internal);
    }

    /**
     * Turn one configured entry into a suffix, or refuse it.
     *
     * @param bool $allowRules false for the internal-domains key and for
     *        discovery, where a rule-scoped suffix would be meaningless
     * @return array{suffix: string, rules: ?array<int, string>, note: ?string}|null
     */
    private function parseEntry(mixed $raw, bool $allowRules = true): ?array
    {
        $rules = null;
        $note = null;
        $value = null;

        if (is_string($raw)) {
            $value = $raw;
        } elseif (is_array($raw)) {
            // Both key names are accepted because the Hub schema for this does
            // not exist yet and both will be written. Refusing one of them would
            // refuse a whole payload over a synonym.
            foreach (['suffix', 'domain'] as $key) {
                if (isset($raw[$key]) && is_string($raw[$key])) {
                    $value = $raw[$key];
                    break;
                }
            }

            if ($allowRules && is_array($raw['rules'] ?? null)) {
                $rules = [];

                foreach ($raw['rules'] as $rule) {
                    if (is_string($rule) && trim($rule) !== '') {
                        $rules[] = strtoupper(trim($rule));
                    }
                }

                // An entry scoped to a list that parsed to nothing would
                // suppress nothing, so it is refused rather than stored as
                // though it were scoped.
                if ($rules === []) {
                    $this->refuse(
                        $this->describe($raw),
                        'empty_rule_scope',
                        'not applied: the entry names a rule scope but no usable rule id, '
                        . 'so it would suppress nothing'
                    );

                    return null;
                }
            }

            if (isset($raw['note']) && is_string($raw['note'])) {
                $note = $raw['note'];
            }
        }

        if (!is_string($value)) {
            $this->refuse($this->describe($raw), 'not_a_domain', 'not applied: no suffix in the entry');

            return null;
        }

        $suffix = $this->normalizeSuffix($value);

        if ($suffix === null) {
            return null;
        }

        return ['suffix' => $suffix, 'rules' => $rules, 'note' => $note];
    }

    /**
     * Normalise a configured suffix and refuse it if it cannot work.
     *
     * The normalisations mirror DnsEventNormalizer::normalizeDomain(), because an
     * entry not normalised the same way as the name it is compared against can
     * never match. Measured, 0 of 23,234 rrnames on this host needed case or
     * trailing-dot correction, so this is not about the traffic: it is about the
     * entry, which is typed by a human and routinely arrives as `Example.COM.`
     * or `*.example.com`.
     */
    private function normalizeSuffix(string $value): ?string
    {
        $suffix = strtolower(trim($value));

        if ($suffix === '') {
            $this->refuse($value, 'empty', 'not applied: the entry is empty');

            return null;
        }

        // The measured cost of matching everything: 100% of 23,234 rows.
        if ($suffix === '*' || $suffix === '.' || $suffix === '*.' || $suffix === '**') {
            $this->refuse(
                $value,
                'match_everything',
                'not applied: this entry would suppress every DNS event on the host '
                . '(measured 100% of 23,234 rows)'
            );

            return null;
        }

        // A leading `*.` is normalised away rather than refused, and the choice
        // is measured rather than aesthetic. Under the usual reading
        // `*.github.com` excludes the apex, and the apex IS queried here: 10 of
        // the 8,342 github.com rows are `github.com` itself. Two readings of one
        // entry differing only on the apex produce exactly one unexplained
        // finding months later, so both forms mean the suffix including its
        // apex, and the normalisation is noted so it is visible rather than
        // inferred.
        $wildcard = str_starts_with($suffix, '*.');

        if ($wildcard) {
            $suffix = substr($suffix, 2);
        }

        $suffix = rtrim($suffix, '.');

        if ($suffix === '') {
            $this->refuse($value, 'empty', 'not applied: the entry is empty');

            return null;
        }

        if (str_contains($suffix, '*') || str_contains($suffix, '?')) {
            // Glob semantics are not implemented, so storing this would store
            // something that can only ever fail to match. `*example.com` is also
            // the shape an operator writes when they mean `.example.com`, and
            // accepting it as a substring pattern is the notexample.com bug with
            // the operator's blessing.
            $this->refuse(
                $value,
                'unsupported_wildcard',
                'not applied: only a leading "*." is understood. Write the suffix itself, '
                . 'which already matches every name under it'
            );

            return null;
        }

        if (preg_match('/[\x80-\xff]/', $suffix) === 1) {
            // A name typed in a non-ASCII script cannot match: Suricata logs the
            // on-wire presentation form, which is punycode. Converted where the
            // intl extension is present, refused where it is not, because
            // storing it would store an entry that never matches. Measured 0
            // non-ASCII and 0 xn-- rrnames in 23,234 rows, so this fires on
            // nothing today and exists for the entry side.
            $converted = function_exists('idn_to_ascii')
                ? idn_to_ascii($suffix, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46)
                : false;

            if (!is_string($converted) || $converted === '') {
                $this->refuse(
                    $value,
                    'non_ascii',
                    'not applied: DNS records are logged in punycode and this entry could not be '
                    . 'converted, so it would never match. Enter the xn-- form'
                );

                return null;
            }

            $suffix = strtolower($converted);
        }

        if (strlen($suffix) > self::MAX_NAME_LENGTH) {
            $this->refuse(
                $value,
                'too_long',
                'not applied: longer than the ' . self::MAX_NAME_LENGTH
                . '-byte limit, so every name under it is a protocol violation'
            );

            return null;
        }

        $labels = explode('.', $suffix);

        foreach ($labels as $label) {
            if ($label === '') {
                $this->refuse($value, 'empty_label', 'not applied: the entry has an empty label');

                return null;
            }

            if (strlen($label) > self::MAX_LABEL_LENGTH) {
                $this->refuse(
                    $value,
                    'too_long',
                    'not applied: the label "' . $label . '" is over ' . self::MAX_LABEL_LENGTH . ' bytes'
                );

                return null;
            }

            // The same character class DnsEventNormalizer flags on, underscore
            // included: _dmarc and _acme-challenge are real names.
            if (preg_match('/^[a-z0-9_-]+$/', $label) !== 1) {
                $this->refuse(
                    $value,
                    'invalid_character',
                    'not applied: "' . $label . '" is not a DNS label, so nothing can match this entry'
                );

                return null;
            }
        }

        if (count($labels) === 1 && !in_array($suffix, self::RESERVED_INTERNAL_SUFFIXES, true)) {
            // A one-label entry is a whole TLD. Measured: `com` would suppress
            // 93.96% of rows and 30 of the 42 distinct names on this host. The
            // dotless names that ARE queried here (nginx-proxy, invalid) need no
            // entry, because the dotless rule already classifies them internal,
            // so this refusal costs nothing measurable.
            $this->refuse(
                $value,
                'single_label',
                'not applied: "' . $suffix . '" has one label, so as a suffix it is a whole '
                . 'top-level domain (on this host "com" alone would suppress 93.96% of DNS '
                . 'events). If it is a dotless host name it needs no entry: dotless names are '
                . 'already classified internal. Otherwise name the domain you mean'
            );

            return null;
        }

        if (in_array($suffix, self::REGISTRY_SUFFIXES, true)) {
            $this->refuse(
                $value,
                'registry_suffix',
                'not applied: anyone can obtain a name under "' . $suffix
                . '", so this entry would also excuse a stranger. Name the specific host'
            );

            return null;
        }

        if ($wildcard) {
            $this->note($suffix, 'wildcard_normalised', 'read as the suffix including its apex');
        }

        return $suffix;
    }

    /**
     * Longest matching suffix in a table, or null.
     *
     * Labels are sliced, never searched for as a substring, which is what makes
     * `example.com.evil.net` and `notexample.com` misses by construction rather
     * than by a guard.
     *
     * The walk starts at the deepest candidate the table could possibly hold, so
     * the number of lookups is min(labels in the name, deepest entry) rather
     * than one per entry. That matters because the name is chosen by whoever is
     * being detected and a tunnelling name has as many labels as it likes.
     *
     * Measured rather than asserted, because the bound is on the lookups and not
     * on the whole call: a synthetic 122-label name classifies in 3.87us against
     * 0.61us for a three-label one, both doing 2 lookups, so the difference is
     * the cost of splitting a longer string and an attacker can make one
     * classification about six times dearer but cannot make it grow with the
     * size of the allowlist. In context, the whole real batch of 23,234 events
     * with two entries configured classifies in 24.8ms. On this host the deepest
     * real name has 7 labels (auth-4.8.5.security-status.secpoll.powerdns.com)
     * and 92.9% of rows have 3.
     *
     * @param array<string, array> $table
     * @param bool $ignoreScope for the install-time and coverage paths, which
     *        ask what an entry covers rather than whether it excuses one rule
     * @return array|null the matching row, most specific first
     */
    private function matchIn(
        string $name,
        array $table,
        int $maxDepth,
        ?string $rule = null,
        bool $ignoreScope = false
    ): ?array {
        if ($table === [] || $maxDepth === 0) {
            return null;
        }

        $labels = explode('.', $name);
        $count = count($labels);
        $start = max(0, $count - $maxDepth);
        $wanted = $rule === null ? null : strtoupper($rule);

        for ($i = $start; $i < $count; $i++) {
            $candidate = implode('.', array_slice($labels, $i));

            if (!isset($table[$candidate])) {
                continue;
            }

            $row = $table[$candidate];
            $scope = $row['rules'] ?? null;

            if ($scope === null || $ignoreScope) {
                return $row;
            }

            // A rule-scoped entry excuses those rules and nothing else, the way
            // an EdrRuleEngine exclusion bound to an account excuses that
            // account only. A caller that named no rule cannot be given the
            // benefit of a scoped entry, because that would widen the scope to
            // everything; it fails towards detection instead and keeps looking
            // for a broader entry.
            if ($wanted !== null && in_array($wanted, $scope, true)) {
                return $row;
            }
        }

        return null;
    }

    /** Merge the three internal sources into one lookup table. */
    private function rebuildInternal(): void
    {
        $this->internal = [];

        foreach (self::RESERVED_INTERNAL_SUFFIXES as $suffix) {
            $this->internal[$suffix] = ['suffix' => $suffix, 'source' => 'reserved'];
        }

        foreach ($this->internalDiscovered as $suffix => $source) {
            $this->internal[$suffix] ??= ['suffix' => $suffix, 'source' => $source];
        }

        foreach ($this->internalFromHub as $suffix => $source) {
            $this->internal[$suffix] ??= ['suffix' => $suffix, 'source' => $source];
        }

        $this->internalDepth = 0;

        foreach (array_keys($this->internal) as $suffix) {
            $this->internalDepth = max($this->internalDepth, $this->depth($suffix));
        }
    }

    /**
     * Whether a suffix is one nobody can obtain a delegation under.
     *
     * This is the test discovery applies: a search domain that is or sits under
     * a reserved suffix, or is dotless, is applied automatically. Anything else
     * is a public zone, and only a human gets to allowlist one of those.
     */
    private function isNonDelegatable(string $suffix): bool
    {
        if ($this->depth($suffix) === 1) {
            return in_array($suffix, self::RESERVED_INTERNAL_SUFFIXES, true);
        }

        return $this->matchIn($suffix, $this->internal, $this->internalDepth, null, true) !== null;
    }

    private function depth(string $name): int
    {
        return count(explode('.', $name));
    }

    /**
     * @return array{verdict: string, reason: string, name: string, entry: ?string, source: ?string}
     */
    private function verdict(
        string $verdict,
        string $reason,
        string $name,
        ?string $entry = null,
        ?string $source = null
    ): array {
        return [
            'verdict' => $verdict,
            'reason' => $reason,
            'name' => $name,
            'entry' => $entry,
            'source' => $source,
        ];
    }

    private function refuse(string $entry, string $reason, string $message): void
    {
        $this->refused[$this->bucket][] = [
            'entry' => $entry,
            'reason' => $reason,
            'message' => $message,
            'source' => $this->bucket,
        ];
    }

    private function note(string $entry, string $note, string $detail): void
    {
        $this->notes[$this->bucket][] = [
            'entry' => $entry,
            'note' => $note,
            'detail' => $detail,
            'source' => $this->bucket,
        ];
    }

    /** A printable form of whatever the Hub sent, for the refusal record. */
    private function describe(mixed $raw): string
    {
        if (is_string($raw)) {
            return $raw;
        }

        if (is_array($raw)) {
            foreach (['suffix', 'domain'] as $key) {
                if (isset($raw[$key]) && is_string($raw[$key])) {
                    return $raw[$key];
                }
            }
        }

        return (string) json_encode($raw);
    }
}
