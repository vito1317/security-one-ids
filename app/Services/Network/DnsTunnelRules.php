<?php

namespace App\Services\Network;

/**
 * Rules for DNS used as a transport rather than as a lookup.
 *
 * A tunnel does not connect to anything. It asks questions, and the questions
 * are the payload: the name carries data upstream, the answer carries data
 * back, and every packet is an ordinary port 53 datagram to the resolver the
 * host is configured to use. Nothing in the socket rules can see it, because
 * from their point of view a tunnel and a name lookup are the same connection
 * to the same resolver on the same port.
 *
 * **The corpus, and its limit first.** Every number here was measured on
 * 22,522 `event_type` dns rows from this host's live /var/log/suricata/eve.json
 * (23:05:29 to 23:51:42 on 28 August, a 2,773 second span): 11,288 queries,
 * 11,234 answers, 42 distinct names, 28 parent domains. That is the whole DNS
 * corpus on this host and not a sample of a larger one, for the reason
 * `DnsEventNormalizer` records: the seven rotated generations (21 to 27 August)
 * hold 0 dns rows between them, and osquery has no DNS table on Linux. The
 * observed rate is 8.12 rows a second, so the 30 second collect cycle
 * (EDR_INTERVAL in security-one-watchdog.sh) hands these rules roughly 244 rows
 * per batch, of which about 122 are queries.
 *
 * Every maximum quoted below was re-measured once the corpus had grown to
 * 33,700 rows over 4,149 seconds, and none of them moved: longest label still
 * 22 bytes, longest name still 47, most distinct names under one parent still 5
 * in a cycle and 6 over the whole corpus, most unique sub-domain bytes still 42.
 * One figure did move and is quoted at its worst value: the distinct ratio past
 * a 40 query floor reached 0.125 in a 60 second window, against 0.089 over the
 * whole corpus.
 *
 * Two consequences follow from 42 distinct names, and they pull in opposite
 * directions. The separation between this host's traffic and a tunnel is
 * enormous, so the thresholds below are not close calls. But a corpus this
 * narrow cannot represent a browsing workstation or a mail server, so no
 * threshold here is set at "just above what was observed"; each one is set far
 * enough above it to leave room for the legitimate shapes this host does not
 * generate, and where such a shape is known and unmeasurable here it is named
 * in the docblock rather than left implied.
 *
 * **These are shape rules, and deliberately need no history.** NET-002, NET-004
 * and NET-006 all refuse to judge until `MIN_HISTORY_DAYS` of baseline exists,
 * because they ask whether a destination is new, and on a freshly deployed
 * agent everything is new. The rules here ask a different question: whether the
 * name carries more data than a name can carry by accident, and whether a
 * parent domain is being used as a channel rather than resolved. Both are
 * absolute, both are answerable in the first cycle after install, and neither
 * one treats novelty as malice. A first-seen domain is not an incident and is
 * not graded as one anywhere in this file; a domain seen every day for a year
 * still fires DNS-013 if it starts behaving like a channel.
 *
 * **Queries only.** Measured, the corpus is 11,288 queries against 11,234
 * answers, which is one lookup logged twice: the query and its answer carry the
 * same rrname, the same rrtype and the same on-wire id. Judging both would
 * double every finding, and the query is the better half to keep because it is
 * this host's own intent and because queries outnumber answers (the 54 row
 * difference is lookups that were never answered), so nothing is lost by
 * reading them. `evaluate()` therefore returns nothing for a `dns_answer`.
 *
 * **Entropy is deliberately not a rule here.** It is the textbook DGA signal
 * and on this host it does not survive contact with the data: the highest
 * leftmost-label Shannon entropy in the corpus is 3.88 bits, on
 * `no-such-host-abc123xyz.invalid`, a real connectivity probe. Published DGA
 * families sit at roughly 3.5 to 4.2. A threshold anywhere in that band puts a
 * legitimate name above the DGA floor, so entropy would contribute nothing but
 * a plausible-looking number. Length, count and repetition are used instead,
 * all three of which separate by more than an order of magnitude below.
 *
 * **The grouping lives here rather than in an aggregator.** DNS needs an
 * aggregate to be judged at all (a single query is never a tunnel), but this
 * one is a hypothesis about attacker behaviour and not a general purpose
 * reduction, so it is not a second `ConnectionAggregator`. That class must not
 * be reused in any case: `ConnectionAggregator::keyFor()` groups on path,
 * remote address, service port and action, which for DNS is
 * ('', resolver, 53, dns_query) for every query this host makes, collapsing a
 * batch of hundreds of names into one row and discarding the only field that
 * matters. An aggregate keyed on the parent domain has the mirror-image
 * problem: it destroys the per-name detail DNS-011 and DNS-012 read. So the
 * batch is grouped here, for these rules, and the per-event rules keep seeing
 * whole events.
 *
 * **What this file deliberately does not do.**
 *
 * Answer volume. The natural measure of a download channel is the size of the
 * rdata that came back, which the normaliser carries as `rdata_bytes` (measured
 * p50 13, p99 78, max 312 bytes). No threshold is set on it, because the corpus
 * contains exactly one TXT answer and the legitimate answers that are large on
 * other hosts are large for the same reason a tunnel's are: DKIM keys, SPF
 * include chains and DNSSEC material all run to hundreds of bytes. There is no
 * basis on this host to draw that line, and drawing it anyway would be a
 * threshold with a measurement-shaped number and no measurement behind it.
 *
 * MX and CNAME as carriers. dnscat2 will tunnel over both, and the measured
 * baseline for each is 0 queries of 11,288, so on this host they look as
 * notable as TXT. They are left out because MX resolution is what any host that
 * sends mail does constantly and this host sends none, so the zero is a
 * property of this host's role rather than of the protocol. TXT and NULL are
 * kept because TXT's zero survives that objection (SPF, DKIM, DMARC and ACME
 * dns-01 all query TXT, and DNS-010 is graded accordingly) and NULL has no
 * remaining legitimate use at all.
 *
 * @see DnsEventNormalizer for the event shape, and for why answer-side fields
 *      are null on a query rather than empty.
 * @see NetworkRuleEngine for the finding structure and the history discipline
 *      these rules deliberately do not need.
 */
class DnsTunnelRules
{
    /**
     * Record types whose only remaining purpose is carrying bytes, with the
     * severity a single query of that type deserves on its own.
     *
     * Measured over 11,288 queries: TXT 1, NULL 0. The one TXT is
     * `auth-4.8.5.security-status.secpoll.powerdns.com`, this host's own
     * PowerDNS asking whether its version is still supported, which is why
     * `isOwnVersionCheck()` exists rather than a bare "any TXT" rule. The
     * module brief recorded TXT as never seen here and therefore inherently
     * suspicious; acting on that literally would have fired on the security
     * product's own DNS server, on a schedule, forever.
     *
     * TXT is graded 'low' because its zero is a fact about this host, not about
     * DNS: SPF, DKIM, DMARC and ACME dns-01 validation are all TXT lookups, so
     * on a host that sends mail or renews certificates the baseline is not zero
     * and a single TXT query is not an incident. It is here to corroborate,
     * exactly as NET-005 is.
     *
     * NULL is graded 'medium', one step higher, because unlike TXT it has no
     * legitimate modern use to be confused with. RFC 1035 defines it as
     * experimental, no resolver library asks for it, and the tools that do
     * (iodine's raw mode, dnscat2) ask for it because it accepts arbitrary
     * bytes. It is still not 'high' on its own: one query is one query, and the
     * escalation for a NULL query inside a channel-shaped group is DNS-013.
     */
    /**
     * Query types that can carry a payload out, and how much that is worth.
     *
     * Keyed on both the symbolic name and the numeric code, and that is not
     * belt-and-braces. Every rrtype in this host's corpus arrives as a symbolic
     * string (A, AAAA, CNAME, HTTPS, NS, SOA, TXT on Suricata 7.0.10), but the
     * corpus contains no NULL query at all, so which spelling this sensor would
     * use for one is unverified here. A carrier arm keyed on a spelling the
     * sensor never emits is a rule that sits on the coverage list and cannot
     * fire, which is the failure this module has already shipped once, so both
     * forms are accepted and the uncertainty is stated rather than assumed away.
     *
     * NULL is graded above TXT because TXT has legitimate uses this host
     * demonstrates (its own PowerDNS version check) while NULL has none.
     */
    private const CARRIER_TYPES = [
        'TXT' => 'low',
        '16' => 'low',
        'NULL' => 'medium',
        '10' => 'medium',
    ];

    /**
     * This host's own PowerDNS version check, the only TXT lookup in the
     * corpus.
     *
     * Matched on the whole name rather than on a suffix, and the loose part is
     * only the version, because `auth-4.8.5` becomes `auth-4.9.0` at the next
     * upgrade and an exact-string exemption would silently start alerting then.
     * The exemption cannot be abused as a bypass: an attacker would have to
     * host the tunnel under secpoll.powerdns.com, which is not theirs, and the
     * pattern leaves no label free to encode payload into.
     */
    private const OWN_VERSION_CHECK = '/^auth-[0-9]+(\.[0-9]+)*\.security-status\.secpoll\.powerdns\.com$/';

    /**
     * A label this long is carrying something.
     *
     * Measured over 11,288 queries and 42 distinct names, the longest label
     * anywhere in the corpus is 22 bytes (`no-such-host-abc123xyz`), p99 is 14
     * and p50 is 3. Not one query has a label of 30 bytes or more, so this sits
     * at 2.0 times the observed maximum and 3.2 times p99.
     *
     * It is 45 rather than 30 because of a family of legitimate long labels
     * this host does not generate and I therefore could not measure: cloud
     * reputation lookups that encode a file digest into one label, which is 32
     * bytes for hex MD5 and 40 for hex SHA-1. A threshold below 45 would fire
     * on every file an endpoint AV product checks. Above 45 the ground belongs
     * to tunnelling: a label may hold 63 bytes on the wire, base32 fits 5 bytes
     * of payload into every 8 of label, and both iodine and dnscat2 pack their
     * labels near that ceiling because the ceiling is their bandwidth. The
     * normaliser's `label_too_long` flag catches only the illegal case (over
     * 63), which is a strict subset of this and would miss every tunnel that
     * stays inside the protocol.
     *
     * The evasion is real and worth stating: 44 byte labels are invisible to
     * this rule. They remain visible to DNS-013, which does not care how long
     * the labels are.
     */
    private const LONG_LABEL_BYTES = 45;

    /**
     * A name this long is carrying something, even if no single label is.
     *
     * The other way to pack a name is many ordinary-looking labels, which
     * defeats DNS-011 entirely. Measured, the longest name in the corpus is 47
     * bytes (`auth-4.8.5.security-status.secpoll.powerdns.com`, 7 labels),
     * p99 32, p50 20, and 0 of 11,288 queries reach 60 bytes.
     *
     * 128 is 2.7 times the observed maximum and half the 253 byte presentation
     * limit from RFC 1035 2.3.4. The margin is sized against the longest
     * legitimate name family I know of that this host does not produce, the
     * IPv6 reverse pointer: 32 nibble labels plus `ip6.arpa` is 72 bytes by
     * construction, still 56 bytes clear of this threshold. Windows and Azure
     * internal names are the next longest family and land in the same region.
     */
    private const LONG_NAME_BYTES = 128;

    /**
     * How many labels of a name are treated as the parent domain.
     *
     * There is no public suffix list in this project and shipping one for this
     * rule would be nine thousand entries of new surface, so the parent is
     * taken by label count, and the batch is grouped at both two and three
     * labels. Both are measured on real traffic below and both are silent on
     * it, which is what makes running both affordable.
     *
     * Two labels is the registrable domain for the whole of this corpus (28
     * parents, all of the form example.com or example.tw). Three labels exists
     * for the case two gets wrong: under a multi-label suffix like co.uk or
     * s3.amazonaws.com, two labels merges unrelated tenants into one group.
     * That error runs in both directions and each direction needs a different
     * depth. A tunnel at tun.evil.co.uk is diluted at depth 2 (the group is
     * co.uk, and any legitimate co.uk traffic in the same batch drags the
     * distinct ratio down) and correctly isolated at depth 3 (evil.co.uk).
     * Conversely a tunnel at payload.evil.com only groups at depth 2, because
     * at depth 3 each name is its own group.
     *
     * Depth 3 cannot invent a false positive that depth 2 did not already have,
     * because a finer grouping can only reduce a group's distinct-name count.
     * What it can do is un-dilute a ratio, so it fires where a name-churning
     * subtree sits inside an otherwise busy parent. That is the intended catch
     * and also the residual risk, which is why DNS-013 is 'high' rather than
     * 'critical' until something corroborates it.
     *
     * Measured at both depths, worst case over any 30 second window in the
     * corpus (the real cycle width): depth 2 reaches 5 distinct names under one
     * parent, depth 3 reaches 1.
     */
    private const GROUP_DEPTHS = [2, 3];

    /**
     * Distinct names under one parent, in one batch, before the shape is worth
     * judging.
     *
     * Measured across every parent in every window of the corpus, at both
     * grouping depths, and unchanged when the corpus grew by half:
     *   30 second windows (the real cycle): max 5 distinct names (depth 2,
     *     cybersecureone.com, its five regional WAF endpoints), max 1 (depth 3)
     *   60 second windows:                  max 5 (depth 2)
     *   300 second windows:                 max 6 (depth 2)
     *   the whole corpus, 4,149 seconds:    max 6 (depth 2), max 1 (depth 3)
     *
     * 24 is 4 times the maximum over the entire corpus and 4.8 times the
     * maximum over a real cycle. It is also, on its own, the volume gate: a
     * group cannot reach 24 distinct names on fewer than 24 queries, which is
     * well clear of the low-volume region where a ratio means nothing (measured
     * at depth 2 over 30 second windows, a real parent reaches a distinct ratio
     * of 0.50 at 10 queries, 0.25 at 20, and 0.056 once it passes 40). A
     * separate query-count gate was tried and removed as redundant: with the
     * ratio below, 24 distinct names already implies between 24 and 32 queries.
     *
     * For a tunnel this is nothing. Each name carries one chunk, so 24 names is
     * roughly one kilobyte of upstream at base32 densities, and dnscat2 or
     * iodine will do it in under a second.
     */
    private const MIN_DISTINCT_NAMES = 24;

    /**
     * Distinct names divided by queries, above which the parent is being used
     * as a channel rather than resolved.
     *
     * This is the ratio that separates a tunnel from a busy service, and it is
     * the reason DNS-013 can be a volume rule without firing on a CDN. The two
     * shapes are opposites: a busy service resolves a few names many times, a
     * tunnel resolves many names once each, and both can be thousands of
     * queries a minute.
     *
     * Measured at depth 2, the highest distinct ratio any real parent reaches
     * past a 40 query floor is 0.125 (cybersecureone.com, 5 names in 40
     * queries, in a 60 second window), 0.119 in a 30 second window and 0.089
     * over the whole corpus (google.com, 4 names in 45 queries). The two
     * busiest parents sit at 0.0011 (cybersecureone.com, 6 names in 5,396
     * queries) and 0.0005 (github.com, 2 in 3,893). At depth 3 the highest past
     * that floor is 0.025.
     *
     * 0.75 is therefore 6 times the worst real measurement, and the gap is
     * not luck. Legitimate resolution on this host is dual stack: every name is
     * queried for A and again for AAAA (measured 5,672 A queries against 5,537
     * AAAA), so each distinct name costs two queries and the ratio is
     * structurally capped near 0.5 before any repetition at all. A tunnel
     * client picks one record type and gets 1.0.
     *
     * The same fact bounds what this rule can see, and the bound is deliberate.
     * A tunnel driven through a dual-stack stub resolver, so that every payload
     * name is asked for A and AAAA, lands at about 0.5 and is missed. Lowering
     * the threshold to catch it would put it exactly where a browser's first
     * visit to a CDN-sharded page sits (30 new names, each resolved twice), and
     * that trade is not worth making blind on a corpus with no browser in it.
     * Such a tunnel is still visible to DNS-011 and DNS-012 if its labels carry
     * a normal amount of payload.
     */
    private const MIN_DISTINCT_RATIO = 0.75;

    /**
     * Unique sub-domain bytes under one parent: the volume DNS-013 reports, and
     * deliberately not a gate and not an escalation.
     *
     * Counted as the sum, over the distinct names in the group, of the part of
     * each name below the parent. It is the closest thing to "how much data was
     * pushed into DNS names", so it belongs in the alert: measured, the largest
     * figure any real parent reaches is 42 bytes (cybersecureone.com: waf,
     * waf-frankfurt, waf-japan, waf-sf, waf-america) in any window at either
     * depth, and a group carrying half a kilobyte is carrying twelve times that.
     *
     * It was a severity escalation in the first version of this rule and that
     * was wrong, for a reason worth keeping written down: it is not independent
     * evidence. Payload bytes are roughly the distinct-name count times the
     * mean label length, and the distinct-name count is what gated the rule in
     * the first place, so escalating on it means escalating on the same
     * observation twice. It showed up immediately in testing, on a synthetic
     * cloud antivirus lookup pattern (30 hashes, one per name), which reached
     * 1,350 bytes with nothing suspicious about it beyond being an unusual use
     * of DNS, and was graded critical for it. Only a carrier record type or a
     * label too long to be a hostname escalates now, because those are separate
     * facts about the traffic. The number stays in the alert text so the reader
     * can see the volume next to what this host's own parents reach.
     */
    private const MEASURED_MAX_PAYLOAD_BYTES = 42;

    /**
     * Per-event rules: is this one query carrying payload, or asking for a
     * record type whose only use is carrying it.
     *
     * @param array $event a normalised DNS event from DnsEventNormalizer
     * @return array<int, array>
     */
    public function evaluate(array $event): array
    {
        // Answers are the same lookup logged a second time (measured 11,288
        // queries against 11,234 answers, same rrname, same rrtype, same
        // on-wire id), so judging them too would double every finding here.
        if ((string) ($event['action'] ?? '') !== 'dns_query') {
            return [];
        }

        $dns = is_array($event['dns'] ?? null) ? $event['dns'] : [];
        $name = (string) ($dns['rrname'] ?? '');

        if ($name === '') {
            return [];
        }

        $rrtype = strtoupper((string) ($dns['rrtype'] ?? ''));
        $findings = [];

        /* DNS-010: a record type whose only remaining use is carrying bytes ---
         * Low on its own by design. The task this rule serves is corroborating
         * DNS-011 or DNS-013, not waking anybody: TXT is what SPF, DKIM, DMARC
         * and ACME dns-01 validation all use, and this host's own measured zero
         * baseline is a fact about a host that sends no mail. */
        if (isset(self::CARRIER_TYPES[$rrtype]) && !$this->isOwnVersionCheck($name)) {
            $findings[] = $this->finding(
                'DNS-010',
                'Query for a DNS record type used to carry data',
                self::CARRIER_TYPES[$rrtype],
                'T1071.004',
                sprintf(
                    '%s query for %s. Measured over 11,288 queries on this host: TXT 1 (this '
                    . "host's own PowerDNS version check, which this rule exempts) and NULL 0. "
                    . '%s is a record type DNS tunnelling tools reach for because it carries '
                    . 'arbitrary bytes, but one such query is not an incident on its own',
                    $rrtype,
                    $name,
                    $rrtype
                )
            );
        }

        $longest = $this->longestLabel($name);

        /* DNS-011: a label carrying more than a label ever carries here ------
         * The direct measure of payload in a name. 0 of 11,288 real queries
         * have a label of even 30 bytes, against a longest observed 22. */
        if ($longest['length'] >= self::LONG_LABEL_BYTES) {
            $findings[] = $this->finding(
                'DNS-011',
                'DNS name contains a label long enough to carry payload',
                'high',
                'T1048',
                sprintf(
                    'Query for a name whose longest label is %d bytes (%s). The longest label in '
                    . '11,288 measured queries on this host is 22 bytes and p99 is 14; nothing real '
                    . 'reaches 30. A label near the 63 byte protocol ceiling is how DNS tunnelling '
                    . 'carries data upstream',
                    $longest['length'],
                    $this->excerpt($longest['label'])
                )
            );
        }

        /* DNS-012: the same payload spread across many ordinary labels -------
         * DNS-011 is evaded by splitting the payload, so length is also
         * measured on the whole name. Longest real name here is 47 bytes and
         * the longest legitimate family this host does not produce, the IPv6
         * reverse pointer, is 72 by construction. */
        if (strlen($name) >= self::LONG_NAME_BYTES) {
            $findings[] = $this->finding(
                'DNS-012',
                'DNS name long enough to carry payload across several labels',
                'medium',
                'T1048',
                sprintf(
                    'Query for a %d byte name in %d labels (%s). The longest name in 11,288 measured '
                    . 'queries here is 47 bytes in 7 labels, and an IPv6 reverse pointer, the longest '
                    . 'legitimate shape in DNS, is 72. Splitting a payload across ordinary looking '
                    . 'labels is how a tunnel stays under a per-label check',
                    strlen($name),
                    count(explode('.', $name)),
                    $this->excerpt($name)
                )
            );
        }

        return $findings;
    }

    /**
     * Judge a whole batch: the per-event rules on every query, and DNS-013 on
     * the parent-domain groups the batch forms.
     *
     * Every finding comes back paired with a real event, so the caller has
     * something to attribute an alert to and needs no special case for the
     * group rule. For a group finding that event is the group's earliest query,
     * which is the first evidence of the channel in this batch.
     *
     * `stats` exists so that quiet cannot be mistaken for absent. A batch too
     * small to reach the distinct-name gate cannot answer the tunnelling
     * question at all, and `basis_for_group_rule` says which of the two
     * happened: no tunnel, or no basis to look for one.
     *
     * @param array<int, array> $events normalised DNS events
     * @return array{findings: array<int, array{event: array, findings: array<int, array>}>, groups: array<int, array>, stats: array}
     */
    public function evaluateBatch(array $events): array
    {
        $results = [];
        $queries = 0;
        $answers = 0;
        $skipped = 0;
        $byRule = [];

        foreach ($events as $event) {
            $action = (string) ($event['action'] ?? '');

            if ($action === 'dns_answer') {
                $answers++;
            } elseif ($action === 'dns_query') {
                $queries++;
            } else {
                // Not a DNS event at all. Counted rather than ignored: a caller
                // that hands this the wrong stream should be able to see that
                // it did, instead of reading an empty finding list as a clean
                // host.
                $skipped++;
                continue;
            }

            $findings = $this->evaluate($event);

            if ($findings !== []) {
                $results[] = ['event' => $event, 'findings' => $findings];

                foreach ($findings as $finding) {
                    $byRule[$finding['rule']] = ($byRule[$finding['rule']] ?? 0) + 1;
                }
            }
        }

        $groups = $this->summarise($events);
        $atGate = 0;

        foreach ($groups as $group) {
            if ($group['distinct'] >= self::MIN_DISTINCT_NAMES) {
                $atGate++;
            }
        }

        foreach ($this->evaluateGroups($groups) as $hit) {
            $results[] = ['event' => $hit['event'], 'findings' => $hit['findings']];

            foreach ($hit['findings'] as $finding) {
                $byRule[$finding['rule']] = ($byRule[$finding['rule']] ?? 0) + 1;
            }
        }

        return [
            'findings' => $results,
            'groups' => $groups,
            'stats' => [
                'queries' => $queries,
                'answers' => $answers,
                'not_dns' => $skipped,
                'window_seconds' => $this->windowSeconds($events),
                'groups' => count($groups),
                'groups_at_distinct_gate' => $atGate,
                // False means no parent domain in this batch had enough
                // distinct names for DNS-013 to reach a verdict either way, so
                // the rule was silent for lack of a basis rather than because
                // it looked and found nothing. Measured on this host that is
                // the normal state: the busiest parent reaches 5 distinct names
                // in a 30 second cycle against a gate of 24, so a quiet DNS-013
                // here is not evidence of the absence of a tunnel, and a caller
                // reporting coverage must say so.
                'basis_for_group_rule' => $atGate > 0,
                'by_rule' => $byRule,
            ],
        ];
    }

    /**
     * Group a batch of queries by parent domain, at every depth in
     * GROUP_DEPTHS.
     *
     * Answers are excluded for the reason `evaluate()` gives: they are the same
     * lookups a second time, and counting them would halve every distinct
     * ratio in a way that depends on how many answers the cycle happened to
     * catch.
     *
     * Reverse-lookup names are counted separately and taken out of both halves
     * of the ratio, not just the numerator. Removing them from the numerator
     * alone would leave a hiding place: a mail server's blocklist zone is
     * hundreds of exempt queries under one parent, and 30 tunnel names in the
     * same group would be diluted to a ratio of 0.09 by a denominator made
     * almost entirely of traffic this rule has already decided not to judge.
     * Excluding them from both means the remaining names are judged on their
     * own, which is what the exemption was meant to say. See
     * `isReverseLookupName()` for what the exemption costs.
     *
     * @param array<int, array> $events normalised DNS events
     * @return array<int, array> one summary per (depth, parent), unordered
     */
    public function summarise(array $events): array
    {
        $groups = [];

        foreach ($events as $event) {
            if ((string) ($event['action'] ?? '') !== 'dns_query') {
                continue;
            }

            $dns = is_array($event['dns'] ?? null) ? $event['dns'] : [];
            $name = (string) ($dns['rrname'] ?? '');

            if ($name === '') {
                continue;
            }

            $rrtype = strtoupper((string) ($dns['rrtype'] ?? ''));
            $time = $this->eventTime($event);

            // An address in front of the name is removed before the name is
            // judged, rather than the name being skipped because of it.
            //
            // The skip was a hiding place. 1.2.3.4.<payload>.example.net has
            // four leading digit labels, so it was reverse-shaped, so it
            // reached none of the counters below — not the distinct-name count,
            // not the longest label, not the payload byte total, not the
            // carrier types. Four digit labels cost an attacker eight
            // characters and bought invisibility from every rule in this file.
            // The note on the exemption claimed such a name "stays visible to
            // DNS-011 and DNS-012 the moment the attacker lengthens a label";
            // it did not, because the skip came first.
            //
            // Stripped, a blocklist lookup collapses to its zone — one repeated
            // name however many addresses are checked, which is what the
            // exemption was for — and a payload behind an address is judged on
            // the payload.
            $remainder = DnsEventNormalizer::reverseLookupRemainder($name);

            foreach (self::GROUP_DEPTHS as $depth) {
                // The name this depth judges, and whether it is judging
                // anything at all.
                //
                // A reverse-shaped name is reduced to what is left after the
                // address, and then kept only if something of it survives below
                // the parent. A PTR lookup reduces to nothing. A blocklist
                // lookup reduces to its zone, which is the parent, so there is
                // no material the sender chose and nothing to judge — the 300
                // addresses in front of it were the only thing that varied, and
                // varying an address is not evidence of a channel.
                //
                // What survives is the case the old skip missed:
                // 1.2.3.4.<payload>.example.net reduces to
                // <payload>.example.net, which does sit below its parent, so it
                // is judged on the payload. Under the skip it reached none of
                // the counters here — not distinct names, not longest label,
                // not payload bytes, not carrier types — so four digit labels
                // cost eight characters and bought invisibility from every rule
                // in this file.
                $judged = $remainder === null ? $name : $remainder;
                $parent = $this->parentDomain($judged, $depth);
                $key = $depth . ':' . $parent;
                $reverse = $remainder !== null
                    && ($remainder === '' || $this->subdomainPart($judged, $parent) === '');

                if (!isset($groups[$key])) {
                    $groups[$key] = [
                        'parent' => $parent,
                        'depth' => $depth,
                        'queries' => 0,
                        'judged_queries' => 0,
                        'distinct' => 0,
                        'ratio' => 0.0,
                        'payload_bytes' => 0,
                        'longest_label' => 0,
                        'carriers' => [],
                        'reverse_names' => 0,
                        'examples' => [],
                        'first_ts' => $time,
                        'last_ts' => $time,
                        'event' => $event,
                        'names' => [],
                        'reverse' => [],
                    ];
                }

                $group = &$groups[$key];
                $group['queries']++;

                if ($time !== null) {
                    $group['first_ts'] = $group['first_ts'] === null ? $time : min($group['first_ts'], $time);
                    $group['last_ts'] = $group['last_ts'] === null ? $time : max($group['last_ts'], $time);

                    // The representative event is the earliest query in the
                    // group, so an alert points at the first evidence of the
                    // channel rather than at whichever row arrived last.
                    if ($time <= ($this->eventTime($group['event']) ?? $time)) {
                        $group['event'] = $event;
                    }
                }

                if ($reverse) {
                    // Keyed on the name as queried, not on the reduction, so
                    // the count says how many addresses were checked rather
                    // than how many zones they were checked against.
                    if (!isset($group['reverse'][$name])) {
                        $group['reverse'][$name] = true;
                        $group['reverse_names']++;
                    }

                    unset($group);

                    continue;
                }

                // Queries that differ only in the address in front of them are
                // one behaviour, not three hundred. Counting each of them
                // would rebuild the dilution the exclusion exists to prevent:
                // at the depth where the blocklist zone is not yet the parent,
                // 300 checks of one zone would sit in the denominator beside
                // the handful of names actually worth judging.
                if ($remainder === null || !isset($group['names'][$judged])) {
                    $group['judged_queries']++;
                }

                // Counted here, below the reverse-lookup skip and excluding this
                // host's own version check, because the escalation this feeds
                // must not be driven by queries the rule has already declared
                // are not evidence. Counting above meant a PTR sweep or the
                // scheduled PowerDNS secpoll could raise a group from high to
                // critical on the strength of rows that were then excluded from
                // every other count in the same group.
                if (isset(self::CARRIER_TYPES[$rrtype]) && !$this->isOwnVersionCheck($judged)) {
                    $group['carriers'][$rrtype] = ($group['carriers'][$rrtype] ?? 0) + 1;
                }

                if (!isset($group['names'][$judged])) {
                    $group['names'][$judged] = true;
                    $group['distinct']++;
                    $group['payload_bytes'] += strlen($this->subdomainPart($judged, $parent));
                    $group['longest_label'] = max($group['longest_label'], $this->longestLabel($judged)['length']);
                }

                unset($group);
            }
        }

        $summaries = [];

        foreach ($groups as $group) {
            $names = array_keys($group['names']);
            unset($group['names'], $group['reverse']);

            // Over the queries this rule is willing to judge, not over every
            // query in the group: see the note on the exemption above.
            $group['ratio'] = $group['judged_queries'] > 0
                ? $group['distinct'] / $group['judged_queries']
                : 0.0;

            // Longest first: those are the names carrying the most, which is
            // what an analyst reading the alert needs to see. Ties break
            // alphabetically so the same batch always produces the same alert
            // text, which is what makes an alert diffable between cycles.
            usort($names, static fn (string $a, string $b): int => [strlen($b), $a] <=> [strlen($a), $b]);
            $group['examples'] = array_slice($names, 0, 3);

            $summaries[] = $group;
        }

        return $summaries;
    }

    /**
     * DNS-013 over a set of group summaries, with one finding per set of names.
     *
     * The same activity appears in a depth 2 group and a depth 3 group, so
     * candidates are taken strongest first (most distinct names, then the more
     * specific parent) and any later candidate that overlaps an accepted one in
     * the name tree is dropped. That reports the tunnel once, attributed to the
     * most specific parent the evidence supports, instead of once per depth.
     *
     * @param array<int, array> $groups summaries from summarise()
     * @return array<int, array{event: array, findings: array<int, array>, group: array}>
     */
    public function evaluateGroups(array $groups): array
    {
        $candidates = [];

        foreach ($groups as $group) {
            $finding = $this->evaluateGroup($group);

            if ($finding !== null) {
                $candidates[] = ['group' => $group, 'finding' => $finding];
            }
        }

        // Specificity first, then weight of evidence.
        //
        // Ordered the other way round — most distinct names first, depth only
        // as a tiebreak — the shallower group won almost every time, because a
        // depth 2 group is a superset of the depth 3 groups beneath it and so
        // can never have fewer names. The tiebreak only decided anything when
        // the counts were exactly equal, so the "most specific parent" this
        // comment promised was really "the least specific one, unless the
        // deeper group happened to contain every name in the shallower one".
        // A single unrelated name one level up was enough to move an alert
        // from d.zen.spamhaus.org to spamhaus.org, which points the responder
        // at a whole registrable domain instead of the label carrying the
        // channel.
        usort($candidates, static function (array $a, array $b): int {
            return [$b['group']['depth'], $b['group']['distinct']]
                <=> [$a['group']['depth'], $a['group']['distinct']];
        });

        $hits = [];
        $accepted = [];

        foreach ($candidates as $candidate) {
            $parent = $candidate['group']['parent'];
            $overlaps = false;

            foreach ($accepted as $taken) {
                if ($parent === $taken
                    || str_ends_with($parent, '.' . $taken)
                    || str_ends_with($taken, '.' . $parent)
                ) {
                    $overlaps = true;
                    break;
                }
            }

            if ($overlaps) {
                continue;
            }

            $accepted[] = $parent;
            $hits[] = [
                'event' => $candidate['group']['event'],
                'findings' => [$candidate['finding']],
                'group' => $candidate['group'],
            ];
        }

        return $hits;
    }

    /**
     * DNS-013 for one parent-domain group.
     *
     * The shape, in one sentence: many names resolved once each under a single
     * parent, which is the exact inverse of a busy service resolving a few
     * names thousands of times. Both gates have to hold, because either alone
     * fires on real traffic. Volume alone is github.com's 3,893 queries.
     * Ratio alone is any parent that happens to be queried twice in a cycle
     * (measured, a real parent reaches a ratio of 0.5 at 10 queries).
     *
     * Severity is 'high' rather than 'critical' unless something independent
     * corroborates it, and the residual it is being honest about is specific.
     * Three shapes reach these gates without being an intrusion: a merged
     * multi-label suffix (no public suffix list here), a service that mints a
     * unique name per request, and cloud reputation lookups that encode a file
     * digest into the name, which are a genuine data channel run by the
     * endpoint's own antivirus. None of them can be told apart from a tunnel by
     * shape alone, so none of them is exempted and all of them are graded at a
     * level that says "look at this", not "act on this".
     *
     * Corroboration is a carrier record type in the group (DNS-010) or a label
     * too long to be a hostname (DNS-011). Both are facts about the traffic
     * that the distinct-name count did not already contain, which is the whole
     * requirement: see MEASURED_MAX_PAYLOAD_BYTES for the escalation that was
     * removed for failing it.
     */
    public function evaluateGroup(array $group): ?array
    {
        $distinct = (int) ($group['distinct'] ?? 0);
        // The judged half of the group, which is what the ratio was taken over.
        // Reporting the raw query count next to a ratio computed without the
        // exempt names would print two numbers that do not divide into each
        // other, and an analyst checking the arithmetic would be right to
        // distrust the rest of the line.
        $queries = (int) ($group['judged_queries'] ?? $group['queries'] ?? 0);
        $ratio = (float) ($group['ratio'] ?? 0.0);

        if ($distinct < self::MIN_DISTINCT_NAMES || $ratio < self::MIN_DISTINCT_RATIO) {
            return null;
        }

        $payload = (int) ($group['payload_bytes'] ?? 0);
        $longest = (int) ($group['longest_label'] ?? 0);
        $carriers = is_array($group['carriers'] ?? null) ? $group['carriers'] : [];

        $corroboration = [];

        if ($carriers !== []) {
            foreach ($carriers as $type => $count) {
                $corroboration[] = sprintf('%d %s quer%s (DNS-010)', $count, $type, $count === 1 ? 'y' : 'ies');
            }
        }

        if ($longest >= self::LONG_LABEL_BYTES) {
            $corroboration[] = sprintf('a %d byte label (DNS-011)', $longest);
        }

        $span = $this->groupSpan($group);

        $reason = sprintf(
            '%d distinct names under %s from %d queries in %s, a distinct-name ratio of %.2f '
            . '(measured ceiling on this host: 6 distinct names under any parent in the whole '
            . 'corpus, and a distinct ratio of 0.125 past a 40 query floor). '
            . 'A busy service resolves few names many times; this is many names resolved once, '
            . 'which is DNS being used as a channel. %d bytes of unique sub-domain data against '
            . '%d for the largest real parent here, longest label %d bytes. Examples: %s',
            $distinct,
            $group['parent'] ?? '?',
            $queries,
            $span,
            $ratio,
            $payload,
            self::MEASURED_MAX_PAYLOAD_BYTES,
            $longest,
            implode(', ', array_map([$this, 'excerpt'], (array) ($group['examples'] ?? [])))
        );

        if (($group['reverse_names'] ?? 0) > 0) {
            // Said out loud in the alert, because an exclusion nobody can see
            // is indistinguishable from a bug.
            $reason .= sprintf(
                '. %d further names under this parent were reverse-lookup shaped and excluded',
                (int) $group['reverse_names']
            );
        }

        if ($corroboration !== []) {
            $reason .= '. Corroborated by ' . implode(', ', $corroboration);
        }

        return $this->finding(
            'DNS-013',
            'Many distinct subdomains resolved once each under one parent domain',
            $corroboration === [] ? 'high' : 'critical',
            'T1071.004',
            $reason
        );
    }

    /**
     * The last `$labels` labels of a name, or the whole name when it has fewer.
     *
     * A single-label name (measured 128 of 22,522 rows here: `nginx-proxy` 124
     * and a bare `invalid` 4) becomes its own parent with no sub-domain part,
     * so it contributes a distinct name and 0 payload bytes and can never
     * reach the gates on its own. That is the intended outcome: a container
     * service name has no parent to tunnel to.
     */
    public function parentDomain(string $name, int $labels = 2): string
    {
        $parts = explode('.', $name);

        if (count($parts) <= $labels) {
            return $name;
        }

        return implode('.', array_slice($parts, -$labels));
    }

    /**
     * Whether a name is a reverse lookup, in the two forms that legitimately
     * produce thousands of distinct names under one parent.
     *
     * This is the one exemption in the file and it is a deliberate blind spot,
     * so it is worth being exact about the trade. A mail server checking DNS
     * blocklists queries `4.3.2.1.zen.spamhaus.org`, and a log pipeline
     * resolving addresses queries `4.3.2.1.in-addr.arpa`: hundreds of distinct
     * names under one parent, each asked once, a distinct ratio of 1.0. That is
     * pixel for pixel the shape DNS-013 keys on, and it is entirely
     * legitimate. Measured on this host the shape appears 0 times in 11,288
     * queries, so nothing here is being suppressed today; it is sized for the
     * customer hosts that do run a mailer.
     *
     * The exemption is drawn as narrowly as the shape allows: the arpa suffixes
     * are unambiguous, and otherwise a name must begin with at least four
     * labels that are nothing but decimal digits, which is an IPv4 address
     * reversed. Hexadecimal is deliberately not accepted, so a payload encoded
     * as short hex labels is not exempt.
     *
     * Kept for the question "is there an address in front of this name", which
     * is all it answers. It is no longer what decides whether a name is judged:
     * summarise() strips the address and judges what is left, because a
     * boolean skip meant four leading digit labels exempted a name from every
     * count in this file. An earlier version of this note claimed such a name
     * stayed visible to DNS-011 and DNS-012; it did not. See
     * DnsEventNormalizer::reverseLookupRemainder() for what the exemption
     * costs now.
     */
    public function isReverseLookupName(string $name): bool
    {
        // Delegated so the DGA rules and these share one predicate. They did
        // not, and the DGA side had no exemption at all.
        return DnsEventNormalizer::isReverseLookupName($name);
    }

    /**
     * The part of a name below its parent, which is the material the sender
     * chose.
     */
    private function subdomainPart(string $name, string $parent): string
    {
        if ($name === $parent || !str_ends_with($name, '.' . $parent)) {
            return '';
        }

        return substr($name, 0, strlen($name) - strlen($parent) - 1);
    }

    /** @return array{length: int, label: string} */
    private function longestLabel(string $name): array
    {
        $longest = '';

        foreach (explode('.', $name) as $label) {
            if (strlen($label) > strlen($longest)) {
                $longest = $label;
            }
        }

        return ['length' => strlen($longest), 'label' => $longest];
    }

    private function isOwnVersionCheck(string $name): bool
    {
        return preg_match(self::OWN_VERSION_CHECK, $name) === 1;
    }

    /**
     * The event's own clock, at the precision eve.json provides.
     *
     * `event_time_wall` is the DNS-only field the normaliser fills with the
     * packet's own microsecond timestamp; `ts` is the same instant truncated to
     * a second. Preferring the former keeps a group's reported span honest at
     * sub-second widths, which is exactly the width a tunnel's burst has.
     */
    private function eventTime(array $event): ?float
    {
        $wall = $event['network']['event_time_wall'] ?? null;

        if (is_int($wall) || is_float($wall)) {
            return (float) $wall;
        }

        $ts = $event['ts'] ?? null;

        return is_int($ts) || is_float($ts) ? (float) $ts : null;
    }

    private function windowSeconds(array $events): ?float
    {
        $first = null;
        $last = null;

        foreach ($events as $event) {
            $time = $this->eventTime($event);

            if ($time === null) {
                continue;
            }

            $first = $first === null ? $time : min($first, $time);
            $last = $last === null ? $time : max($last, $time);
        }

        return $first === null ? null : round($last - $first, 6);
    }

    private function groupSpan(array $group): string
    {
        $first = $group['first_ts'] ?? null;
        $last = $group['last_ts'] ?? null;

        if (!is_float($first) && !is_int($first)) {
            // Nothing in the batch carried a usable clock. Said rather than
            // printed as "0s", which would read as an instantaneous burst.
            return 'a window of unknown width';
        }

        $span = (float) $last - (float) $first;

        return $span < 1.0 ? sprintf('%.2fs', $span) : sprintf('%ds', (int) round($span));
    }

    /**
     * A name or label, bounded, for an alert line.
     *
     * Truncated because these strings are attacker-controlled and go into
     * alerts, logs and the spool: a 253 byte name in every one of a hundred
     * findings is a log volume problem, and the length is already stated
     * numerically next to it. The rrname itself is carried on the event, so
     * nothing is lost for whoever needs the whole thing.
     */
    private function excerpt(string $value, int $limit = 64): string
    {
        return strlen($value) <= $limit ? $value : substr($value, 0, $limit) . '...';
    }

    private function finding(string $rule, string $name, string $severity, string $mitre, string $reason): array
    {
        return [
            'rule' => $rule,
            'name' => $name,
            'severity' => $severity,
            'mitre' => $mitre,
            'reason' => $reason,
        ];
    }
}
