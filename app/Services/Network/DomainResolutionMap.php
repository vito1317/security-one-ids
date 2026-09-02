<?php

namespace App\Services\Network;

use Illuminate\Support\Facades\Log;
use PDO;
use PDOException;

/**
 * Which domain resolved to an address, so a connection can be given a name.
 *
 * This is the attribution path for DNS telemetry, and it is worth saying why it
 * is the only one that works. Suricata sees the resolution but no process; the
 * socket sensor sees the process but only an address. The obvious join, "the
 * process that talked to the resolver", is useless on this host: the resolver
 * endpoint is 8.8.8.8:53 for 22,418 of 22,418 measured DNS rows, so every
 * process shares one destination and attributing by resolver attributes
 * everything to everything. The RESOLVED address is the join that discriminates,
 * and this class is the index that makes it answerable in the useful direction.
 *
 * Measured on this host, over the 22,418 `event_type":"dns"` rows in
 * /var/log/suricata/eve.json between 23:05:29 and 23:51:19 on 28 August (see
 * the corpus limit below), through `DnsEventNormalizer`:
 *
 *   - 11,182 answers, of which 5,992 (53.6%) named at least one address,
 *     yielding 7,044 (domain, address) observations.
 *   - 43 distinct queried names, 35 of which resolved to an address, over 112
 *     distinct addresses and 128 distinct (domain, address) pairs.
 *   - 7 of those 112 addresses (6.3%) are claimed by more than one domain.
 *
 * And that is the input. The output was measured by replaying it through this
 * class against this host's real socket telemetry: the 4,066 external
 * `net_connect` events the spool holds inside the same window, interleaved in
 * timestamp order so each lookup only sees the answers that had actually
 * arrived before that connection.
 *
 *   - 2,145 of 4,066 (52.8%) got a domain at all.
 *   - 1,489 (36.6%) got exactly one, which is the answer that can be put in
 *     front of a human.
 *   - 656 (16.1%) landed on an address more than one domain claims, which is
 *     30.6% of everything attributed.
 *   - Of the 1,921 that got nothing, 1,920 were addresses no answer in the
 *     corpus ever named and exactly 1 was a mapping that had expired. Coverage
 *     here is limited by what this host resolves, not by the retention below.
 *
 * The unresolved remainder is dominated by 46 addresses, led by 167.172.226.55
 * (163 connections) and 64.23.177.101 (161): scanners this host talks back to,
 * addresses configured as literals, and connections whose resolution happened
 * before the logger was switched on.
 *
 * **The corpus limit, first, because every rate below inherits it.** DNS
 * logging only reaches the live eve.json. The seven rotated generations (21 to
 * 27 August) contain 0 dns rows between them and osquery has no DNS table on
 * Linux, so the whole DNS corpus on this host is 46 minutes of one evening.
 * Anything stated here per hour or per day is an extrapolation from 45.8
 * minutes, and is labelled as one. A ceiling sized from it is sized with margin
 * for that reason and not because the margin is free.
 *
 * **Several domains claiming one address is normal, and picking one is worse
 * than declining.** 30.6% of the attributions above landed on an address
 * claimed by more than one domain, far higher than the 6.3% address figure
 * because the shared addresses are the busy ones: 410 of those 656 lookups
 * came back with seven or eight candidates. The worst address is
 * 125.228.166.197, with 9 domains on it, and it is this product's own front end
 * (waf.cybersecureone.com, waf-sf, waf-japan, waf-frankfurt and waf-america,
 * plus pai.vito1317.com and logify.intellitrustme.com). Returning one of the
 * nine would be right about one connection in nine and would look exactly as
 * confident as a correct answer, in an alert a human then reads as fact. So
 * `domainFor()` returns every live candidate and sets `domain` only when there
 * is exactly one. A caller that reads `domain` alone degrades to "we do not
 * know", which is true, rather than to a name, which usually is not.
 *
 * All 7 shared addresses were shared concurrently (the domains' observation
 * windows overlap), and 0 showed one domain handing an address to another. That
 * is a property of a 46-minute window, not of the internet: reassignment is a
 * thing that happens on the timescale of a cloud provider recycling an
 * elastic IP, which is precisely why mappings expire below rather than
 * accumulating.
 *
 * **What this class deliberately does not do.** It does not read a log (the
 * caller hands it already normalised answers, for the reason
 * `NetworkCollector` and `DnsEventNormalizer` both give: two cursors over one
 * file turn "why did DNS miss this" into a question about which cursor was
 * where). It does not judge anything, so there are no findings and no
 * thresholds of the alerting kind here. And it is not a retro-hunt index:
 * `prune()` deletes, so a question about a month ago has to be asked of the
 * spooled DNS events, which keep every answer, rather than of this store.
 *
 * @see DnsEventNormalizer for the event shape `recordAnswer()` reads, and for
 *      why an address is canonicalised before it is used as a key.
 * @see NetworkBaselineStore for the store conventions this follows (its own
 *      SQLite file, 0600, WAL, and never throwing out into a collect cycle).
 */
class DomainResolutionMap
{
    /**
     * How long past the TTL a mapping stays usable, in seconds.
     *
     * The TTL is the resolver's instruction about caching, not a statement
     * about when the process will use the answer, and measured on this host the
     * gap between the two is what makes a grace necessary. Over the 2,146 of
     * those 4,066 connections that can be matched to an earlier resolution at
     * all, the delay between the answer and the connection was p50 0 s, p75
     * 3 s, p90 162 s, p99 576 s and max 1,776 s, while the TTL on those answers
     * was p50 114 s and p99 300 s. The slow tail is real traffic, not an
     * artefact: a process resolves once and keeps the answer.
     *
     * Measured against those 2,146 matches, the retention policy decides how
     * many survive to be attributable: TTL exactly 2,056 (95.8%), TTL + 60 s
     * 2,102 (97.9%), TTL doubled 2,099 (97.8%), TTL + 300 s 2,145 (99.95%),
     * TTL + 900 s 2,145, TTL + 1,800 s 2,146 (100%). 300 s is where the curve
     * flattens. The single match it misses is that 1,776 s outlier, and buying
     * it would mean holding every mapping for half an hour past its TTL, which
     * is thirty minutes in which the address may have been reassigned and this
     * store would keep vouching for the old name. One missed attribution is a
     * gap; a wrong attribution is a false accusation, and the two are not worth
     * trading one for one.
     *
     * The grace is also the floor, and that matters more than it looks:
     * 1,228 of the 7,044 address observations (17.4%) carried a TTL of 30 s or
     * less and two carried 0. Obeying the TTL alone would drop one mapping in
     * six within half a minute of learning it, which is shorter than the
     * interval between two collect cycles.
     */
    private const TTL_GRACE = 300;

    /**
     * The longest a mapping may live, whatever the TTL said.
     *
     * The TTL is supplied by whoever owns the domain, which on the traffic this
     * module exists to detect means it is supplied by the attacker. A C2 domain
     * is free to publish a TTL of 2,147,483,647, and without a cap that single
     * answer would pin its mapping in this store for 68 years and keep naming
     * an address long after it had been handed to somebody else. Six hours is
     * generous against everything real here and cheap against that.
     *
     * Measured, it bites on 0 of the 7,044 address observations: the longest
     * TTL on an answer that named an address was 873 s, so the longest
     * retention this host actually produces is 1,173 s. It is a bound on
     * hostile input, not a tuning knob, which is why it is not derived from the
     * measured distribution.
     */
    private const MAX_RETENTION = 21600;

    /**
     * The most (domain, address) pairs the store will hold after a prune.
     *
     * Sized from the measured rate the way `NetworkBaselineStore` sizes
     * retention, by asking how much history the number buys. This host produced
     * 128 distinct pairs in 45.8 minutes, which is 167.6 an hour and, taking
     * that 46-minute rate at face value, about 4,000 a day. 20,000 rows is
     * therefore around 119 hours of pair discovery, five days, against a
     * maximum retention of six hours: the ceiling can only bite if pruning has
     * been failing for days or the rate has risen by roughly two orders of
     * magnitude.
     *
     * Two things bound the damage a burst can do here, and both are measured.
     * Only answers that named an address are recorded, so the 255 NXDOMAIN
     * answers in the corpus produced 0 rows: a DGA sweeping thousands of names
     * that do not exist cannot fill this store at all. And the busiest domain
     * for distinct addresses was redirector.gvt1.com at 24 addresses in 46
     * minutes, so ordinary CDN churn is nowhere near the ceiling.
     *
     * Eviction is oldest-first on `last_seen`, and it is reported. That is the
     * right order for an index whose value is answering questions about
     * connections happening now, and it is safe here for a reason that would
     * not hold in a baseline: this store never judges novelty, so evicting old
     * rows cannot make anything look new. Detecting the burst that caused the
     * eviction is the rule engine's job on the event stream, and the eviction
     * count is how the burst stays visible from here.
     */
    private const MAX_MAPPINGS = 20000;

    private ?PDO $pdo = null;
    private string $path;

    /**
     * Its own normaliser, deliberately not the caller's.
     *
     * `normalizeDomain()` is reused rather than reimplemented so that a lookup
     * key and a baseline key are spelled the same way (lowercased, trailing dot
     * stripped) even after somebody turns on 0x20 encoding. But the instance is
     * private on purpose: that method counts its rejections on the object, and
     * sharing the sensor's normaliser would file a lookup for an unusable
     * domain in the same tally as a rejected log row, which is the one number a
     * reader uses to decide whether the DNS sensor has gone blind. This class
     * counts its own refusals in `skips()` and `misses()` instead.
     */
    private DnsEventNormalizer $domains;

    /** For `unmapIpv4()`, so one address has one spelling across all sensors. */
    private SocketEventNormalizer $sockets;

    /** @var array<string, int> reason => count, for lookups that answered nothing */
    private array $misses = [];

    /** @var array<string, int> reason => count, for writes that recorded nothing */
    private array $skips = [];

    public function __construct(?string $path = null)
    {
        $this->path = $path ?? storage_path('app/edr/dns-map.sqlite');
        $this->domains = new DnsEventNormalizer();
        $this->sockets = new SocketEventNormalizer();
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function close(): void
    {
        $this->pdo = null;
    }

    /* ------------------------------------------------------------------ */
    /* Writing                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Record that a domain resolved to these addresses at this instant.
     *
     * Returns the number of (domain, address) pairs written, so a caller can
     * report progress and tell a quiet resolver from a broken store. Anything
     * not written is counted in `skips()` by reason rather than dropped
     * quietly.
     *
     * Re-observing a pair refreshes its expiry from the newest observation,
     * because that is what the resolver just said. It is guarded on `last_seen`
     * so an out-of-order row cannot walk the expiry backwards: rows arrive from
     * a log batch in file order, several flows interleave in it, and 81 of the
     * 128 measured pairs had their TTL change between observations, so the
     * value being refreshed with is genuinely not always the same.
     *
     * @param array<int, string> $addresses as `DnsEventNormalizer` spells them
     * @param int|null           $ttl       the answer's TTL, null when it had none
     * @param int               $ts        the event time, not now()
     */
    public function record(string $domain, array $addresses, ?int $ttl, int $ts): int
    {
        $name = $this->domains->normalizeDomain($domain);

        if ($name === null) {
            return $this->skip('bad_domain');
        }

        if ($ts <= 0) {
            // Every expiry is derived from this, so a placeholder timestamp
            // would produce a mapping that is either already dead or immortal.
            return $this->skip('bad_timestamp');
        }

        if ($addresses === []) {
            // Not an error and worth its own name: 5,190 of the 11,182 measured
            // answers named no address, most of them AAAA lookups of A-only
            // names. The resolver succeeded and there is simply nothing here to
            // index.
            return $this->skip('no_addresses');
        }

        $expires = $ts + $this->retentionFor($ttl);
        $written = 0;
        // Prepared once for the whole answer rather than once per address. Not
        // a micro-optimisation: the measured maximum was 24 addresses in one
        // answer (redirector.gvt1.com) and this runs inside the collect cycle.
        $stmt = null;

        foreach ($addresses as $raw) {
            $address = $this->addressKey($raw);

            if ($address === null) {
                $this->skip('bad_address');
                continue;
            }

            try {
                $stmt ??= $this->pdo()->prepare(
                    'INSERT INTO mappings
                        (address, domain, ttl, first_seen, last_seen, expires_at, observations)
                     VALUES (?, ?, ?, ?, ?, ?, 1)
                     ON CONFLICT(address, domain) DO UPDATE SET
                        observations = mappings.observations + 1,
                        first_seen = MIN(mappings.first_seen, excluded.first_seen),
                        ttl = CASE WHEN excluded.last_seen >= mappings.last_seen THEN excluded.ttl ELSE mappings.ttl END,
                        expires_at = CASE WHEN excluded.last_seen >= mappings.last_seen THEN excluded.expires_at ELSE mappings.expires_at END,
                        last_seen = MAX(mappings.last_seen, excluded.last_seen)'
                );
                $stmt->execute([$address, $name['name'], $ttl, $ts, $ts, $expires]);
                $written++;
            } catch (PDOException $e) {
                // Never thrown out: this runs inside a collect cycle, and
                // losing an attribution hint must not lose the batch of events
                // it came with.
                $this->skip('store_unavailable');
                Log::debug('[EDR dns] record failed: ' . $e->getMessage());
            }
        }

        return $written;
    }

    /**
     * Record from a normalised DNS event.
     *
     * The one place that knows the event shape, so the field names live here
     * rather than in every caller. Queries and addressless answers are not
     * errors and are counted as themselves: a query carries `addresses` null
     * because that kind of event cannot know, an answer carries [] because the
     * resolver replied and named nothing, and `DnsEventNormalizer` keeps those
     * two apart precisely so this method does not have to guess.
     */
    public function recordAnswer(array $event): int
    {
        if (($event['action'] ?? null) !== 'dns_answer') {
            return $this->skip('not_an_answer');
        }

        $dns = is_array($event['dns'] ?? null) ? $event['dns'] : [];
        $addresses = is_array($dns['addresses'] ?? null) ? $dns['addresses'] : [];

        return $this->record(
            (string) ($dns['rrname'] ?? ''),
            $addresses,
            isset($dns['ttl']) ? (int) $dns['ttl'] : null,
            (int) ($event['ts'] ?? 0)
        );
    }

    /**
     * How long a mapping learned from an answer with this TTL stays usable.
     *
     * Public because it is the policy, and a test that restates the arithmetic
     * instead of asking for it is a test of its own copy of the policy.
     */
    public function retentionFor(?int $ttl): int
    {
        // A missing TTL is not a short TTL, and it is not a long one either. It
        // gets the grace alone, which at 300 s is still longer than the measured
        // median TTL of 114 s, so an answer that carried no TTL is not
        // penalised against one that carried a typical one. It is measured at 0
        // of 7,044 observations here; the branch exists because "the field was
        // absent" and "the field said zero" must not become the same number by
        // accident.
        $base = $ttl === null ? 0 : max(0, $ttl);

        return min($base + self::TTL_GRACE, self::MAX_RETENTION);
    }

    /* ------------------------------------------------------------------ */
    /* Reading                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Which domain resolved to this address, as far as this store can say.
     *
     * Null means this store cannot name the address, and the reason is counted
     * in `misses()` so the caller can tell the nulls apart: nothing has ever
     * been recorded at all (`no_basis`), this address was never seen
     * (`unknown_address`), it was seen and its mapping has expired (`expired`),
     * it was only learned after the instant asked about (`learned_after`), what
     * was passed is not an address (`bad_address`), or the store could not be
     * read (`store_unavailable`). Only `unknown_address` is a fact about the
     * address; the rest are facts about this store, and a caller that treats
     * them alike will report a host whose connections have no domains behind
     * them. A stale mapping is never returned as a current one: an expired row
     * is filtered out by the query, so it stops answering the moment it expires
     * whether or not `prune()` has run since.
     *
     * `domain` is set only when exactly one live mapping exists, and
     * `candidates` always carries all of them, ordered newest claim first with
     * the domain name as a deterministic tiebreak. The ordering exists so a
     * human reading an alert sees the most recent claim first and must never be
     * read as a pick: on this host 30.6% of the connections this store could
     * name at all landed on an address with more than one claimant, and the
     * busiest of them has nine.
     *
     * @param string   $address the connection's remote address
     * @param int|null $at      the instant to answer for, defaulting to now.
     *                          Pass the connection's own timestamp: asking
     *                          "who owns this address now" about a connection
     *                          from twenty minutes ago drops mappings that were
     *                          live when it happened. The row keeps only its
     *                          newest observation's expiry, so a question about
     *                          the past is answered from the window
     *                          first_seen..expires_at and cannot see whether
     *                          the mapping lapsed and was re-learned inside it.
     * @return array{address: string, domain: ?string, unique: bool, candidate_count: int, candidates: array<int, array{domain: string, ttl: ?int, first_seen: int, last_seen: int, expires_at: int, observations: int}>}|null
     */
    public function domainFor(string $address, ?int $at = null): ?array
    {
        $key = $this->addressKey($address);

        if ($key === null) {
            return $this->miss('bad_address');
        }

        $now = $at ?? time();

        try {
            $stmt = $this->pdo()->prepare(
                'SELECT domain, ttl, first_seen, last_seen, expires_at, observations
                   FROM mappings
                  WHERE address = ? AND expires_at > ? AND first_seen <= ?
                  ORDER BY last_seen DESC, domain ASC'
            );
            $stmt->execute([$key, $now, $now]);
            $rows = $stmt->fetchAll();
        } catch (PDOException $e) {
            // A broken store must not be able to say "this address was never
            // resolved here", which is a finding. It says nothing, loudly.
            Log::debug('[EDR dns] domainFor failed: ' . $e->getMessage());

            return $this->miss('store_unavailable');
        }

        if ($rows === []) {
            return $this->miss($this->whyNothing($key, $now));
        }

        $candidates = array_map(static fn (array $row): array => [
            'domain' => (string) $row['domain'],
            'ttl' => $row['ttl'] === null ? null : (int) $row['ttl'],
            'first_seen' => (int) $row['first_seen'],
            'last_seen' => (int) $row['last_seen'],
            'expires_at' => (int) $row['expires_at'],
            'observations' => (int) $row['observations'],
        ], $rows);

        return [
            'address' => $key,
            // Null on an ambiguous address on purpose. A caller that reads only
            // this field then fails to "unknown", which is honest, instead of
            // to whichever of nine domains sorted first.
            'domain' => count($candidates) === 1 ? $candidates[0]['domain'] : null,
            'unique' => count($candidates) === 1,
            'candidate_count' => count($candidates),
            'candidates' => $candidates,
        ];
    }

    /**
     * The addresses this domain is currently known to resolve to.
     *
     * Returns bare address strings, ordered newest observation first, because
     * this direction is a membership test: the caller has a domain and wants to
     * know whether a connection belongs to it. The metadata lives on the
     * reverse direction, where the several-claimants problem is, and where a
     * caller has to be able to see how strong each claim is.
     *
     * An empty array is not "no basis": a domain with no live addresses may
     * never have been recorded, or may resolve only to AAAA records this host
     * never asked for, or may have had its mappings expire. Ask `basis()` before
     * reading an empty result as a fact about the domain.
     *
     * @return array<int, string>
     */
    public function addressesFor(string $domain, ?int $at = null): array
    {
        $name = $this->domains->normalizeDomain($domain);

        if ($name === null) {
            $this->miss('bad_domain');

            return [];
        }

        $now = $at ?? time();

        try {
            $stmt = $this->pdo()->prepare(
                'SELECT address FROM mappings
                  WHERE domain = ? AND expires_at > ? AND first_seen <= ?
                  ORDER BY last_seen DESC, address ASC'
            );
            $stmt->execute([$name['name'], $now, $now]);

            return array_map('strval', $stmt->fetchAll(PDO::FETCH_COLUMN));
        } catch (PDOException $e) {
            Log::debug('[EDR dns] addressesFor failed: ' . $e->getMessage());
            $this->miss('store_unavailable');

            return [];
        }
    }

    /**
     * Why a lookup found nothing, told apart rather than lumped together.
     *
     * "We have never recorded anything" and "this address was resolved by
     * nothing" are the same null and completely different facts, and only the
     * second is evidence of any kind. Both queries are cheap: the address
     * counts hit the primary key, and the basis check hits the expiry index and
     * stops at the first row.
     */
    private function whyNothing(string $address, int $now): string
    {
        try {
            $stmt = $this->pdo()->prepare(
                'SELECT SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END) AS expired,
                        SUM(CASE WHEN first_seen > ? THEN 1 ELSE 0 END) AS later
                   FROM mappings WHERE address = ?'
            );
            $stmt->execute([$now, $now, $address]);
            $row = $stmt->fetch();

            if (is_array($row) && (int) ($row['expired'] ?? 0) > 0) {
                return 'expired';
            }

            if (is_array($row) && (int) ($row['later'] ?? 0) > 0) {
                return 'learned_after';
            }

            $live = $this->pdo()->prepare('SELECT 1 FROM mappings WHERE expires_at > ? LIMIT 1');
            $live->execute([$now]);

            return $live->fetchColumn() === false ? 'no_basis' : 'unknown_address';
        } catch (PDOException $e) {
            return 'store_unavailable';
        }
    }

    /* ------------------------------------------------------------------ */
    /* Housekeeping                                                        */
    /* ------------------------------------------------------------------ */

    /**
     * Drop what has expired, then anything above the ceiling, and say what went.
     *
     * The two counts are reported separately because they mean different
     * things. `expired` is the store working: a mapping outlived its TTL plus
     * grace and was never renewed. `evicted` is the store being overrun, which
     * at the measured 167.6 pairs an hour should take five days of failed
     * pruning to reach, so a non-zero value is a fact about the host and not
     * about this class.
     *
     * @return array{available: bool, expired: int, evicted: int, remaining: int, ceiling: int}
     */
    public function prune(?int $now = null): array
    {
        $now ??= time();
        $result = ['available' => false, 'expired' => 0, 'evicted' => 0, 'remaining' => 0, 'ceiling' => self::MAX_MAPPINGS];

        try {
            $pdo = $this->pdo();
            $result['available'] = true;

            $stmt = $pdo->prepare('DELETE FROM mappings WHERE expires_at <= ?');
            $stmt->execute([$now]);
            $result['expired'] = $stmt->rowCount();

            $remaining = (int) $pdo->query('SELECT COUNT(*) FROM mappings')->fetchColumn();

            if ($remaining > self::MAX_MAPPINGS) {
                // Oldest last_seen first: the value of this index is answering
                // questions about connections happening now, and it never
                // judges novelty, so losing old rows cannot make anything look
                // new. The address tiebreak keeps the choice deterministic
                // rather than rowid order.
                $stmt = $pdo->prepare(
                    'DELETE FROM mappings WHERE rowid IN (
                        SELECT rowid FROM mappings ORDER BY last_seen ASC, address ASC LIMIT ?
                     )'
                );
                $stmt->execute([$remaining - self::MAX_MAPPINGS]);
                $result['evicted'] = $stmt->rowCount();

                Log::warning('[EDR dns] Resolution map ceiling hit, dropped oldest mappings', [
                    'evicted' => $result['evicted'],
                    'ceiling' => self::MAX_MAPPINGS,
                ]);
            }

            $result['remaining'] = $remaining - $result['evicted'];
        } catch (PDOException $e) {
            Log::warning('[EDR dns] Resolution map prune failed: ' . $e->getMessage());
        }

        return $result;
    }

    /**
     * Whether there is any basis to judge, and how much of one.
     *
     * The question a caller has to ask before reading a null from `domainFor()`
     * as anything at all. `window_seconds` is how much history the store
     * actually spans, which on a freshly started agent is minutes: absence of
     * history is not evidence of intrusion, and this is the number that says
     * so.
     *
     * @return array{available: bool, mappings: int, live: int, domains: int, addresses: int, oldest_first_seen: ?int, newest_last_seen: ?int, window_seconds: int, ambiguous_addresses: int}
     */
    public function basis(?int $now = null): array
    {
        $now ??= time();
        $empty = [
            'available' => false, 'mappings' => 0, 'live' => 0, 'domains' => 0, 'addresses' => 0,
            'oldest_first_seen' => null, 'newest_last_seen' => null, 'window_seconds' => 0,
            'ambiguous_addresses' => 0,
        ];

        try {
            $stmt = $this->pdo()->prepare(
                'SELECT COUNT(*) AS mappings,
                        SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END) AS live,
                        COUNT(DISTINCT domain) AS domains,
                        COUNT(DISTINCT address) AS addresses,
                        MIN(first_seen) AS oldest,
                        MAX(last_seen) AS newest
                   FROM mappings'
            );
            $stmt->execute([$now]);
            $row = $stmt->fetch();

            if (!is_array($row)) {
                return $empty;
            }

            $shared = $this->pdo()->prepare(
                'SELECT COUNT(*) FROM (
                    SELECT address FROM mappings WHERE expires_at > ?
                     GROUP BY address HAVING COUNT(DISTINCT domain) > 1
                 )'
            );
            $shared->execute([$now]);

            $oldest = $row['oldest'] === null ? null : (int) $row['oldest'];
            $newest = $row['newest'] === null ? null : (int) $row['newest'];

            return [
                'available' => true,
                'mappings' => (int) $row['mappings'],
                'live' => (int) $row['live'],
                'domains' => (int) $row['domains'],
                'addresses' => (int) $row['addresses'],
                'oldest_first_seen' => $oldest,
                'newest_last_seen' => $newest,
                'window_seconds' => $oldest === null || $newest === null ? 0 : max(0, $newest - $oldest),
                'ambiguous_addresses' => (int) $shared->fetchColumn(),
            ];
        } catch (PDOException $e) {
            Log::warning('[EDR dns] Resolution map basis unavailable: ' . $e->getMessage());

            return $empty;
        }
    }

    public function stats(?int $now = null): array
    {
        return $this->basis($now) + [
            'path' => $this->path,
            'ceiling' => self::MAX_MAPPINGS,
            'ttl_grace' => self::TTL_GRACE,
            'max_retention' => self::MAX_RETENTION,
            'misses' => $this->misses,
            'skips' => $this->skips,
        ];
    }

    public function isAvailable(): bool
    {
        try {
            $this->pdo();

            return true;
        } catch (PDOException $e) {
            Log::warning('[EDR dns] Resolution map unavailable: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * Lookups that answered nothing, by reason, since the last reset.
     *
     * Same discipline as `DnsEventNormalizer::rejections()`, for the same
     * reason: a store that returns null and counts nothing is how attribution
     * quietly stops working. A schema change, a permission change or an empty
     * database turns every lookup into a null, and the batch looks like a host
     * whose connections simply have no domains behind them.
     *
     * @return array<string, int>
     */
    public function misses(): array
    {
        return $this->misses;
    }

    /**
     * Writes that recorded nothing, by reason, since the last reset.
     *
     * @return array<string, int>
     */
    public function skips(): array
    {
        return $this->skips;
    }

    public function resetCounters(): void
    {
        $this->misses = [];
        $this->skips = [];
    }

    /* ------------------------------------------------------------------ */
    /* Internals                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Spell an address the way every other sensor here spells it.
     *
     * On both the write and the read path, because the measured trap is
     * symmetric: 791 of 791 IPv6 addresses under `dns.grouped.AAAA` arrive
     * fully expanded while osquery and Suricata's flow fields use the
     * compressed form, so a store keyed on one and queried with the other joins
     * nothing at all and reports a host whose IPv6 connections have no domains.
     * `DnsEventNormalizer` already canonicalises what it emits, and this repeats
     * it rather than trusting that every future caller came through it.
     */
    private function addressKey(string $address): ?string
    {
        $value = trim($address);

        if ($value === '') {
            return null;
        }

        $unmapped = $this->sockets->unmapIpv4($value);

        if (filter_var($unmapped, FILTER_VALIDATE_IP) === false) {
            // A hostname or an AF_UNIX path is not an address, and storing one
            // here would make it look like a resolution. CNAME targets are the
            // realistic way this happens: they sit next to the addresses in a
            // grouped answer section.
            return null;
        }

        $binary = @inet_pton($unmapped);

        if ($binary === false) {
            return $unmapped;
        }

        $canonical = @inet_ntop($binary);

        return $canonical === false ? $unmapped : $canonical;
    }

    /** Always returns null, so a caller can `return $this->miss(...)`. */
    private function miss(string $reason): null
    {
        $this->misses[$reason] = ($this->misses[$reason] ?? 0) + 1;

        return null;
    }

    /** Always returns 0, so a caller can `return $this->skip(...)`. */
    private function skip(string $reason): int
    {
        $this->skips[$reason] = ($this->skips[$reason] ?? 0) + 1;

        return 0;
    }

    private function pdo(): PDO
    {
        if ($this->pdo instanceof PDO) {
            return $this->pdo;
        }

        $dir = dirname($this->path);

        if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
            throw new PDOException("Cannot create DNS resolution map directory: {$dir}");
        }

        $pdo = new PDO('sqlite:' . $this->path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_TIMEOUT => 10,
        ]);

        $pdo->exec('PRAGMA journal_mode = WAL');
        $pdo->exec('PRAGMA synchronous = NORMAL');
        $pdo->exec('PRAGMA busy_timeout = 10000');

        $this->pdo = $pdo;
        $this->migrate();

        // The store holds which internal names this host resolves and when,
        // which is a map of the estate. Same mode as the other EDR stores.
        @chmod($this->path, 0600);

        return $this->pdo;
    }

    private function migrate(): void
    {
        // Address first in the primary key, because the hot query is by
        // address: a connection arrives with one and needs a name. That order
        // lets the same index serve the lookup and the uniqueness constraint.
        //
        // `ttl` is stored as the resolver reported it, including null, rather
        // than as the retention derived from it. The derived number is in
        // expires_at; keeping the raw value means a later change to the grace
        // is visible as a policy change instead of being indistinguishable from
        // the resolver having said something different.
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS mappings (
                address      TEXT NOT NULL,
                domain       TEXT NOT NULL,
                ttl          INTEGER,
                first_seen   INTEGER NOT NULL,
                last_seen    INTEGER NOT NULL,
                expires_at   INTEGER NOT NULL,
                observations INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (address, domain)
            )
        SQL);

        // The reverse direction, for addressesFor().
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_map_domain ON mappings (domain)');
        // Prune deletes on this, and the basis check stops at its first row.
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_map_expiry ON mappings (expires_at)');
        // Eviction reads this in order, oldest first.
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_map_last_seen ON mappings (last_seen)');
    }
}
