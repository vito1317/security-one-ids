<?php

namespace App\Services\Network;

/**
 * Turns a Suricata eve.json `dns` record into the shared normalised event shape.
 *
 * Everything asserted here was measured on this host's own DNS telemetry. The
 * corpus and its limit both matter, so the limit comes first: DNS logging only
 * reaches the live `/var/log/suricata/eve.json`. The seven rotated generations
 * (eve.json.1.gz through .7.gz, 21 to 27 August) contain 0 rows of
 * `event_type":"dns"` between them, and osquery has no DNS table on Linux, so
 * the whole DNS corpus available on this host is what has accumulated in the
 * live file since the logger was turned on. That was 6,394 rows over the first
 * 13 minutes, and 21,092 rows over 40 minutes (23:05:29 to 23:45:55 on
 * 28 August) by the time this class was verified against them. Numbers below
 * are stated against those 21,092 rows unless they say otherwise; no proportion
 * moved between the two corpora.
 *
 * **Only this host's own resolution appears.** src_ip was 192.168.1.114 (this
 * host) on 21,088 of 21,092 rows, with 2 on 127.0.0.1 and 2 on a container
 * bridge; dest_port was 53 on 21,092 of 21,092. Inbound queries to the
 * authoritative PowerDNS are bypassed upstream and never reach the logger, so
 * every event here is this host asking, never this host answering. A rule that
 * reads these as "queries we received" would be describing the wrong host.
 *
 * **The gate is `event_type`, not the presence of a `dns` member.** In the same
 * file, 10,895 `alert` rows and 4,954 `flow` rows carry a `dns` member or
 * `app_proto: dns`, and 369 of those alert rows carry a real rrname nested one
 * level deeper, under `dns.query[]`. That shape is deliberately not read.
 * Verified on flow_id 1835623357181964: the alert row and the `event_type` dns
 * row carry the same name (api.telegram.org), the same on-wire id (45074) and
 * the same timestamp to the microsecond. Ingesting both would double count
 * every query that happens to trip a signature, which is to say precisely the
 * queries a detector cares most about.
 *
 * **One entry point, not two.** A query and an answer become different actions
 * ('dns_query' and 'dns_answer'), but they arrive interleaved on one stream and
 * the field that tells them apart (`dns.type`) is inside the row. Two public
 * methods would push that dispatch into every caller, and a caller that gets it
 * wrong does not fail loudly, it silently files answers as queries. So the row
 * is classified once, here, and the kind it turned out to be is carried in both
 * `action` and `dns.type`.
 *
 * **Why the two actions must stay distinct.** Measured over 10,522 answers,
 * 4,673 of them (44.4%) carried rcode NOERROR and no address at all. 4,607 were
 * AAAA lookups of names that have only A records, which a resolver answers
 * NOERROR with an SOA in the authority section, and the other 66 were HTTPS, NS
 * and TXT lookups where an address was never what was asked for. A detector
 * that treated "query with no answer" and "answer with no address" as one thing
 * would call 44% of this host's successful DNS resolution a failed lookup.
 *
 * **The clock.** eve.json timestamps are ISO 8601 with an offset and
 * microseconds (`2026-08-28T23:05:29.636989+0800`); all 21,092 matched
 * `Y-m-d\TH:i:s.uP` and all carried +0800. Unlike the osquery path there is no
 * flush clock here and nothing to anchor against boot time: Suricata writes the
 * packet's own time, so this timestamp IS the event time, and `ts` needs no
 * correction of the kind `SocketEventNormalizer::eventTime()` applies. The
 * microsecond value is carried through as well, because DNS beaconing is a
 * question about inter-arrival gaps and whole seconds cannot answer it.
 *
 * **rrtype is wider than the module brief says, and one value in it is us.**
 * Measured across the corpus: A (10,556), AAAA (10,404), HTTPS (126, the SVCB
 * record current browsers and curl now ask for alongside A and AAAA), NS (4)
 * and TXT (2).
 * The TXT rows matter because the brief for this module records TXT as absent
 * from the baseline and therefore inherently suspicious, TXT being the classic
 * tunnelling carrier. Both rows are
 * auth-4.8.5.security-status.secpoll.powerdns.com, which is this host's own
 * PowerDNS asking whether its version is still supported (it answered
 * "3 Unsupported release (EOL)"). A rule that treated any TXT as out of
 * baseline would therefore fire, on a schedule, on the security product's own
 * DNS server. Nothing here judges rrtype; the value is carried verbatim so the
 * rule that does can be written against what this host actually emits.
 *
 * **Two socket-path helpers must not be reused on these events, and the shape
 * makes both look safe.** The `network` sub-array is filled in so that a DNS
 * event and a socket event describing one peer agree, which is what makes them
 * comparable, and it is also what makes the wrong reuse compile.
 *
 * `SocketEventNormalizer::shouldDrop()` drops loopback unconditionally and
 * private by default. That is right for socket telemetry and ruinous here: a
 * host running a stub resolver (systemd-resolved on 127.0.0.53, dnsmasq, or a
 * container resolver on the docker bridge) sends every query to a loopback or
 * private address, so the filter would discard 100% of DNS visibility and
 * report a quiet network. This host queries 8.8.8.8 directly, so only 4 of
 * 21,092 rows were loopback or private, which is precisely why the trap is
 * invisible from these numbers rather than absent.
 *
 * `ConnectionAggregator::keyFor()` groups on path, remote address, service port
 * and action. For DNS that is ('', resolver, 53, dns_query) for every query
 * this host makes, so a batch of thousands of lookups of hundreds of names
 * collapses into one group and the rrname, which is the only interesting field,
 * is discarded. Whatever aggregates DNS has to group by rrname.
 *
 * **No process attribution exists in this data.** Suricata sees packets, so pid,
 * uid, path and cmdline are not "not yet filled in", they are unavailable at
 * source. They are populated with the same placeholders the rest of the shape
 * uses (pid 0, uid -1, empty strings) and pid 0 here means "unknown", never
 * "the kernel". Attaching a process is `SuricataCorrelator`'s job, through the
 * flow's peer address and port.
 *
 * One consequence for whoever writes the rules: the socket path drops its own
 * sensors' traffic by binary name (`SocketEventNormalizer::AGENT_BINARIES`) and
 * this path cannot, because there is no binary to name. Measured, the busiest
 * domain in the corpus is this product's own control plane
 * (waf.cybersecureone.com, 9,036 of 21,092 rows, ahead of api.github.com at
 * 7,700), so a DNS baseline built from this stream contains the agent's own
 * destinations and a rarity rule has to be told about them by domain rather
 * than by process.
 *
 * @see SocketEventNormalizer for the shape this matches and the `network`
 *      sub-array convention.
 */
class DnsEventNormalizer
{
    /**
     * The end of the flow on this port is the resolver.
     *
     * Measured: dest_port was 53 on 21,092 of 21,092 rows, and src_port was 53
     * on 0 of 10,522 answers, so Suricata logs the answer with the flow's
     * original orientation rather than the response packet's. The flipped
     * branch below is therefore defensive and fires on nothing today. It is
     * kept because a Suricata release that logged response packets in packet
     * order would otherwise write the resolver into `local_address` and this
     * host into `remote_address` for every answer, inverting the whole DNS
     * baseline without producing a single error.
     */
    private const RESOLVER_PORT = 53;

    /**
     * Presentation-form limits, RFC 1035 2.3.4 and 3.1.
     *
     * Measured on real traffic the margin is enormous: longest name 47 bytes
     * (p50 20, p90 22, p99 32), longest single label 22. Exceeding either limit
     * is a
     * protocol violation, and this class FLAGS it rather than rejecting it,
     * because a long name in many labels is the DNS-tunnelling carrier itself.
     * A validator that dropped over-long names would delete the evidence for
     * the one detection this module exists to make, and would report a clean
     * result while doing it.
     */
    private const MAX_NAME_LENGTH = 253;
    private const MAX_LABEL_LENGTH = 63;

    /**
     * Accepted timestamp shapes, parsed strictly.
     *
     * `strtotime()` is not used, and that is a deliberate difference from
     * `SuricataCorrelator::alertTime()`. strtotime accepts relative English
     * ("tomorrow", "+1 day", "now"), so a corrupted or attacker-influenced
     * timestamp field does not fail, it yields a confident wrong instant, and
     * an event time is what every rate and interval rule is built on. A strict
     * format parse returns the logged instant or nothing.
     *
     * Only offset-bearing forms are accepted, and an offsetless timestamp is
     * rejected rather than read in whatever timezone the process happens to
     * have. Measured on this host, that is not one timezone: PHP's ini default
     * is UTC (so the test suite and any bare CLI script read UTC) while the
     * application sets APP_TIMEZONE=Asia/Taipei, and the log itself carries
     * +0800. An offsetless stamp would therefore resolve to two instants eight
     * hours apart depending on whether the reader booted the framework, and an
     * event time that depends on which process read the log is not an event
     * time. Every row carries an offset today (21,092 of 21,092, all +0800), so
     * this rejects nothing real; the fractional part is optional because it is
     * a Suricata build option.
     */
    private const TIMESTAMP_FORMATS = [
        'Y-m-d\TH:i:s.uP',
        'Y-m-d\TH:i:sP',
    ];

    /**
     * Reused rather than reimplemented, for scope classification and for
     * unwrapping IPv4-mapped IPv6.
     *
     * Not a style choice: `SuricataCorrelator` joins DNS-adjacent flows against
     * socket events by address string, and a second scope classifier that drifts
     * from the first would put the same address in two buckets depending on
     * which sensor saw it. There is one classifier and both paths call it.
     */
    private SocketEventNormalizer $sockets;

    /** @var array<string, int> reason => count */
    private array $rejections = [];

    public function __construct(?SocketEventNormalizer $sockets = null)
    {
        $this->sockets = $sockets ?? new SocketEventNormalizer();
    }

    /**
     * Normalise one already-decoded eve.json row.
     *
     * @param array $event the whole eve.json object
     * @return array|null the normalised event, or null when the row is not a
     *                    DNS record this class models, with the reason counted
     *                    in rejections()
     */
    public function normalize(array $event): ?array
    {
        if (($event['event_type'] ?? null) !== 'dns') {
            return $this->reject('not_dns_event');
        }

        $dns = $event['dns'] ?? null;

        if (!is_array($dns)) {
            return $this->reject('no_dns_object');
        }

        $action = match ((string) ($dns['type'] ?? '')) {
            'query' => 'dns_query',
            'answer' => 'dns_answer',
            // Anything else is a shape this class does not model. eve.json also
            // carries dns records under `query[]` and `answer[]` arrays in
            // other event types, and guessing would file a fragment of an alert
            // as a resolution this host performed.
            default => $this->reject('unknown_dns_type'),
        };

        if ($action === null) {
            return null;
        }

        // Counts its own rejection reason, so a null here is already explained.
        $domain = $this->normalizeDomain($dns['rrname'] ?? null);

        if ($domain === null) {
            return null;
        }

        $time = $this->eventTime($event['timestamp'] ?? null);

        if ($time === null) {
            return $this->reject('bad_timestamp');
        }

        $isAnswer = $action === 'dns_answer';
        $flow = $this->orient($event);
        $resolver = $flow['resolver'];

        // Answer-side facts are null on a query rather than empty. The
        // distinction is load-bearing: null means "this kind of event does not
        // carry that fact", [] means "the resolver answered and named no
        // address". Collapsing them is how the 4,673 measured NOERROR answers
        // that named no address would read as failed lookups.
        $answer = $isAnswer ? $this->answerFacts($dns) : null;

        return [
            'ts' => (int) $time,
            // eve.json carries no host identifier: 0 of 21,092 rows had a
            // `host` member, because Suricata only writes one when
            // eve-log.sensor-name is set. Read anyway so a host that sets it
            // wins over this process's own idea of its name.
            'host' => (string) ($event['host'] ?? gethostname()),
            'action' => $action,
            'sensor' => 'suricata-dns',
            // Unavailable at source, not missing. Suricata sees packets and has
            // no idea which process resolved the name; pid 0 means unknown here
            // and must never be read as the kernel.
            'pid' => 0,
            'ppid' => 0,
            'uid' => -1,
            'username' => '',
            'path' => '',
            'cmdline' => '',
            'cwd' => '',
            'container_id' => '',
            // No syscall was observed. Left empty rather than invented as
            // 'sendto', which would claim telemetry we do not have.
            'syscall' => '',
            'network' => [
                'remote_address' => $resolver['address'],
                'remote_port' => $resolver['port'],
                'local_address' => $flow['client']['address'],
                // Real here, and worth saying because it is the opposite of the
                // socket path: local_port is 0 on 100% of osquery
                // bpf_socket_events rows, while every one of the 21,092 DNS
                // rows carried a genuine ephemeral source port. It is the field
                // that makes a query and its answer joinable to one flow.
                'local_port' => $flow['client']['port'],
                'family' => $this->family($resolver['address']),
                'protocol' => $this->protocolNumber($event['proto'] ?? null),
                'scope' => $this->sockets->classifyScope($resolver['address']),
                'count' => 1,
                'first_seen' => (int) $time,
                'last_seen' => (int) $time,
                'intervals' => [],
                // Deliberately null, and deliberately present. eve.json has no
                // kernel clock, so there is no monotonic value to put here; the
                // aggregator reads this key and falls back to whole seconds,
                // which means DNS regularity cannot be established from it
                // rather than being established wrongly. Filling it with the
                // wall clock would break that field's contract, which is that
                // it is only ever valid to subtract two of them.
                'event_time_monotonic' => null,
                // The wall-clock event time with the microseconds eve.json
                // actually provides. The osquery path has no equivalent (its
                // precise clock is monotonic and its wall clock is a batch
                // flush time), so this is a DNS-only field, and it is what a
                // beacon or burst rule should read.
                'event_time_wall' => $time,
            ],
            'dns' => [
                'type' => $isAnswer ? 'answer' : 'query',
                'rrname' => $domain['name'],
                // Carried only when normalisation changed something, so that a
                // change is visible rather than inferred. Measured: 0 of 21,092
                // rows needed either fix (see normalizeDomain).
                'rrname_raw' => $domain['changed'] ? $domain['raw'] : null,
                'rrtype' => isset($dns['rrtype']) ? strtoupper((string) $dns['rrtype']) : null,
                'domain_valid' => $domain['flags'] === [],
                'domain_flags' => $domain['flags'],
                'rcode' => $answer['rcode'] ?? null,
                'addresses' => $answer['addresses'] ?? null,
                'address_count' => $answer === null ? null : count($answer['addresses']),
                'record_types' => $answer['record_types'] ?? null,
                'rdata_bytes' => $answer['rdata_bytes'] ?? null,
                'ttl' => $answer['ttl'] ?? null,
                'answer_count' => $answer['answer_count'] ?? null,
                'authority_only' => $answer['authority_only'] ?? null,
                // The on-wire DNS id, which is the field that actually joins a
                // query to its answer: present on 21,092 of 21,092 rows.
                'transaction_id' => $this->intOrNull($dns['id'] ?? null),
                // Suricata's own per-flow transaction counter, which is a
                // different thing and is not a join key. Measured, it was
                // present on 10,570 of 10,570 queries and 0 of 10,522 answers,
                // so a correlator keyed on tx_id would match nothing at all.
                'tx_id' => $this->intOrNull($dns['tx_id'] ?? null),
                // The flow this resolution belongs to, for joining against the
                // alert, http and tls records of the same flow.
                'flow_id' => $this->intOrNull($event['flow_id'] ?? null),
            ],
        ];
    }

    /**
     * Normalise one raw log line.
     *
     * Takes a line rather than reading the log itself, for the reason
     * NetworkCollector gives: every bug in a log cursor is silent, the shared
     * LogCursor has already had three of them found and fixed, and a second
     * cursor over eve.json would reintroduce them one at a time while making
     * "why did the DNS module miss this" a question about which cursor was
     * where. `SuricataCorrelator` and the DNS path therefore share one cursor
     * and each get the decoded rows.
     *
     * The decode lives here rather than in the caller so that an undecodable
     * line is counted with the other rejections instead of being swallowed by
     * whatever loop is reading. A partially written trailing line is the normal
     * steady state of a live log; LogCursor already withholds the partial tail,
     * so a non-zero `json_decode` count means something else is truncating
     * lines, which is worth being able to see.
     */
    public function normalizeLine(string $line): ?array
    {
        if (trim($line) === '') {
            return $this->reject('empty_line');
        }

        $row = json_decode($line, true);

        if (!is_array($row)) {
            return $this->reject('json_decode');
        }

        return $this->normalize($row);
    }

    /**
     * Lowercase, strip the trailing dot, and report what is implausible.
     *
     * Both normalisations were measured against real traffic and both fired on
     * nothing: of 21,092 rows, 0 had a trailing dot and 0 had any uppercase
     * character, and neither did the 11,552 rrnames nested inside them (6,661
     * answer records and 4,891 authority records). That measurement is the
     * argument FOR doing it rather than against, for two reasons.
     *
     * DNS comparison is case-insensitive on the wire, and 0x20 encoding (the
     * standard anti-spoofing trick, one config line in unbound and BIND, and
     * the default in some stub resolvers) randomises the case of every outgoing
     * query. The absence of mixed case here is a property of this host's
     * current resolver, not of DNS. Turn 0x20 on and a baseline keyed on the
     * raw string sees a brand new domain on almost every query: a "never seen
     * before" rule then fires on all of it, and a frequency baseline never
     * converges. The same argument holds for an attacker who simply varies the
     * case, which costs nothing and needs no resolver support.
     *
     * The trailing dot is the same problem from the other side: Suricata's
     * version 2 dns records strip it, but the fully qualified form with the
     * root dot is what most other DNS tooling emits, and one module joining
     * "api.github.com" against another's "api.github.com." matches nothing.
     *
     * Rejection is kept as narrow as the evidence allows. A name is rejected
     * only when there is nothing usable to key on (absent, not a string, empty,
     * or nothing but dots) or when it contains a control character or
     * whitespace, which cannot be written to a log line or used as a store key
     * without corrupting one of them. Suricata escapes genuinely non-printable
     * bytes in presentation form, so an unescaped one means the row itself is
     * not trustworthy.
     *
     * Everything else is flagged and carried. The single-label case is why:
     * `nginx-proxy` is not a plausible public domain, but it is a real query
     * this host makes (a Docker service name, 124 of 21,092 rows, with 4 more
     * for a bare `invalid`, 0.6% together), so rejecting single-label names
     * would silently delete real telemetry. Measured on 21,092 rows, every
     * other flag fired 0 times:
     * label_too_long 0, name_too_long 0, empty_label 0, hyphen_edge 0,
     * non_ldh_character 0. They exist because that is the exact shape a
     * tunnelling or DGA name has, and a flag with a measured zero on clean
     * traffic is a usable discriminator, whereas a drop is a blind spot.
     *
     * @return array{name: string, raw: string, changed: bool, flags: array<int, string>}|null
     */
    public function normalizeDomain(mixed $rrname): ?array
    {
        if (!is_string($rrname)) {
            return $this->reject('no_rrname');
        }

        $raw = $rrname;

        // Checked before anything is stripped, and whitespace counts as
        // unprintable: a name carrying a space or a newline cannot be written
        // to a log line or used as a store key without corrupting one of them,
        // and trimming it quietly would turn a malformed row into a plausible
        // one.
        if (preg_match('/[\x00-\x20\x7f]/', $raw) === 1) {
            return $this->reject('rrname_unprintable');
        }

        $name = strtolower(rtrim($raw, '.'));

        if ($name === '') {
            // Covers both the absent case and a bare root query ('.'), which
            // has no domain to judge and nothing to baseline.
            return $this->reject('no_rrname');
        }

        $labels = explode('.', $name);
        $flags = [];

        if (count($labels) === 1) {
            $flags[] = 'single_label';
        }

        if (strlen($name) > self::MAX_NAME_LENGTH) {
            $flags[] = 'name_too_long';
        }

        foreach ($labels as $label) {
            if ($label === '') {
                $flags[] = 'empty_label';
                continue;
            }

            if (strlen($label) > self::MAX_LABEL_LENGTH) {
                $flags[] = 'label_too_long';
            }

            if ($label[0] === '-' || substr($label, -1) === '-') {
                $flags[] = 'hyphen_edge';
            }

            // Underscore is allowed without comment: _dmarc, _acme-challenge
            // and _tcp service names are legitimate and common, so flagging
            // them would put noise in front of the shapes that matter.
            if (preg_match('/^[a-z0-9_-]+$/', $label) !== 1) {
                $flags[] = 'non_ldh_character';
            }
        }

        return [
            'name' => $name,
            'raw' => $raw,
            'changed' => $name !== $raw,
            'flags' => array_values(array_unique($flags)),
        ];
    }

    /**
     * The event time as a unix second with the logged fraction kept.
     *
     * Returned as a float so the caller can take whole seconds for `ts` and
     * keep the microseconds for interval work. Null when the field is absent or
     * does not match a known shape; the caller rejects the row rather than
     * substituting now(), because a DNS event placed at the wrong instant
     * corrupts every rate and gap measurement built on it, and unlike the
     * osquery path there is no second clock in the row to fall back to.
     */
    public function eventTime(mixed $timestamp): ?float
    {
        if (!is_string($timestamp) || $timestamp === '') {
            return null;
        }

        $value = trim($timestamp);

        // ISO 8601 spells UTC as 'Z'; the format character P does not accept
        // it. Measured 0 of 21,092 rows on this host, kept because it is what
        // an eve-log configured for UTC emits.
        if (str_ends_with($value, 'Z') || str_ends_with($value, 'z')) {
            $value = substr($value, 0, -1) . '+0000';
        }

        foreach (self::TIMESTAMP_FORMATS as $format) {
            $parsed = \DateTimeImmutable::createFromFormat($format, $value);

            if ($parsed === false) {
                continue;
            }

            // createFromFormat succeeds with warnings on trailing rubbish and
            // on impossible dates it silently rolls over (32 January becomes
            // 1 February). Both are rejected: a rolled-over date is a wrong
            // answer wearing the shape of a right one.
            $errors = \DateTimeImmutable::getLastErrors();

            if (is_array($errors) && (($errors['warning_count'] ?? 0) > 0 || ($errors['error_count'] ?? 0) > 0)) {
                continue;
            }

            return (float) $parsed->format('U') + ((int) $parsed->format('u')) / 1_000_000;
        }

        return null;
    }

    /**
     * Which end of the flow is the resolver.
     *
     * @return array{resolver: array{address: ?string, port: ?int}, client: array{address: ?string, port: ?int}}
     */
    public function orient(array $event): array
    {
        $src = ['address' => $this->address($event['src_ip'] ?? null), 'port' => $this->port($event['src_port'] ?? null)];
        $dest = ['address' => $this->address($event['dest_ip'] ?? null), 'port' => $this->port($event['dest_port'] ?? null)];

        // The port-53 end is the resolver. Reading it from the port rather than
        // assuming dest keeps this correct if a future Suricata logs answers in
        // packet order; measured, that has not happened (0 of 10,522 answers
        // had src_port 53), so this normally takes the first branch.
        if ($src['port'] === self::RESOLVER_PORT && $dest['port'] !== self::RESOLVER_PORT) {
            return ['resolver' => $src, 'client' => $dest];
        }

        return ['resolver' => $dest, 'client' => $src];
    }

    /**
     * The facts that only an answer carries.
     *
     * `addresses` comes from `dns.grouped`, A before AAAA, which makes the list
     * deterministic so anything keyed on it is stable. Only A and AAAA are
     * folded in. CNAME, NS and TXT also appear under `grouped` (measured 5,667
     * answers carried a grouped section, of which 67 held no A or AAAA at all:
     * 36 CNAME only, 28 an empty section, 2 NS and 1 TXT), and putting a name
     * into a list of addresses
     * would send a hostname into address reputation lookups as though it were
     * an IP.
     *
     * `ttl` is the minimum across the answer section, not the first. The
     * shortest TTL in a CNAME chain is the one that governs when the client
     * must ask again, and shortening it is what fast-flux and short-lease C2
     * infrastructure does. Measured over 6,661 answer records: min 1, p50 144,
     * p90 300, max 86,400.
     *
     * `record_types` and `rdata_bytes` exist because "addresses" is not the
     * whole answer and the interesting answers are the ones with no address in
     * them. Measured over 10,522 answers, the grouped section held: A only
     * 5,152 times, no section at all 4,855, AAAA only 412, CNAME only 36, A
     * with CNAME 36, an empty section 28, NS 2 and TXT 1. Without the type
     * list, those 36 CNAME-only answers and the TXT look identical to a
     * resolver that said nothing, and TXT is
     * the classic tunnelling carrier. `rdata_bytes` is the volume that came
     * back, all types included: min 0, p50 13 (the length of a dotted quad),
     * p90 15, p99 78, max 312. The payload itself is deliberately not carried,
     * because an answer's rdata can be arbitrary bytes and this event goes into
     * a spool, but its size is the signal that separates resolution from
     * transport.
     *
     * `authority_only` records the case that makes a null result honest: an
     * answer with no answer section but an authority section present. Measured
     * 4,855 of 10,522 answers, of which 4,606 were NOERROR (mostly AAAA lookups
     * of A-only names) and 249 were NXDOMAIN. It says "the resolver replied and
     * named no address", which is a different fact from "we never saw a reply".
     *
     * @return array{rcode: ?string, addresses: array<int, string>, record_types: array<int, string>, rdata_bytes: int, ttl: ?int, answer_count: int, authority_only: bool}
     */
    private function answerFacts(array $dns): array
    {
        $records = is_array($dns['answers'] ?? null) ? $dns['answers'] : [];
        $grouped = is_array($dns['grouped'] ?? null) ? $dns['grouped'] : [];

        $addresses = [];

        foreach (['A', 'AAAA'] as $type) {
            foreach (is_array($grouped[$type] ?? null) ? $grouped[$type] : [] as $rdata) {
                if (!is_string($rdata) || filter_var($rdata, FILTER_VALIDATE_IP) === false) {
                    // Measured, 0 of the 6,494 values under A or AAAA in a
                    // grouped section were anything but an address. Dropped
                    // rather than carried, because the only consumers of this
                    // list treat its members as IPs.
                    continue;
                }

                $address = $this->canonicalAddress($rdata);

                if (!in_array($address, $addresses, true)) {
                    $addresses[] = $address;
                }
            }
        }

        $types = [];
        $rdataBytes = 0;

        foreach ($grouped as $type => $values) {
            if (!is_array($values) || $values === []) {
                continue;
            }

            $types[] = strtoupper((string) $type);

            foreach ($values as $value) {
                if (is_string($value)) {
                    $rdataBytes += strlen($value);
                }
            }
        }

        sort($types);

        $ttl = null;

        foreach ($records as $record) {
            $candidate = is_array($record) ? $this->intOrNull($record['ttl'] ?? null) : null;

            if ($candidate !== null && ($ttl === null || $candidate < $ttl)) {
                $ttl = $candidate;
            }
        }

        return [
            'rcode' => isset($dns['rcode']) && is_string($dns['rcode']) ? strtoupper($dns['rcode']) : null,
            'addresses' => $addresses,
            'record_types' => $types,
            'rdata_bytes' => $rdataBytes,
            'ttl' => $ttl,
            'answer_count' => count($records),
            'authority_only' => $records === [] && is_array($dns['authorities'] ?? null) && $dns['authorities'] !== [],
        ];
    }

    /**
     * Rejections since the last reset, by reason.
     *
     * Exposed because a normaliser that returns null and counts nothing is how
     * a sensor goes blind without anybody noticing: a parser change, a Suricata
     * upgrade or a schema version bump turns every row into a null, and the
     * batch looks like a quiet network. The caller reports these next to the
     * kept count so "we saw nothing" can be told apart from "nothing happened".
     *
     * @return array<string, int>
     */
    public function rejections(): array
    {
        return $this->rejections;
    }

    public function resetRejections(): void
    {
        $this->rejections = [];
    }

    /** Always returns null, so callers can `return $this->reject(...)`. */
    private function reject(string $reason): null
    {
        $this->rejections[$reason] = ($this->rejections[$reason] ?? 0) + 1;

        return null;
    }

    /**
     * The socket family, as the string the osquery path uses.
     *
     * Derived from the address because eve.json does not carry a family field.
     * The numbers are Linux AF_INET and AF_INET6 so that a DNS event and a
     * socket event describing the same peer agree on this field.
     */
    private function family(?string $address): ?string
    {
        if ($address === null) {
            return null;
        }

        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return '2';
        }

        return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? '10' : null;
    }

    /**
     * The IP protocol number, matching osquery's numeric `protocol` column.
     *
     * Measured: proto was 'UDP' on 21,092 of 21,092 rows. TCP is mapped because
     * DNS over TCP is what a large answer or a zone transfer uses, and a
     * tunnelling client that wants throughput will reach for it.
     */
    private function protocolNumber(mixed $proto): ?int
    {
        if (!is_string($proto)) {
            return null;
        }

        return match (strtoupper(trim($proto))) {
            'UDP' => 17,
            'TCP' => 6,
            default => null,
        };
    }

    private function address(mixed $value): ?string
    {
        if (!is_string($value) || trim($value) === '' || trim($value) === 'unknown') {
            return null;
        }

        return $this->canonicalAddress(trim($value));
    }

    /**
     * Spell an address the way every other sensor here spells it.
     *
     * This is not cosmetic, and it was the one genuine surprise in the data.
     * Measured on the real corpus, 791 of 791 IPv6 addresses under
     * `dns.grouped.AAAA` arrived fully expanded
     * ("2001:4860:4840:0400:0000:0000:0000:0000"), while osquery's socket rows
     * and Suricata's own flow fields use the compressed form
     * ("2001:4860:4840:400::"). Carried through verbatim, every IPv6 resolution
     * from this path would fail to join the connection that followed it and
     * fail to match any address baseline: not an error, just a class of
     * destination that silently never correlates. IPv4 needed no change, 0 of
     * 5,703 differed.
     *
     * IPv4-mapped IPv6 is unwrapped through the shared helper first, because
     * osquery reports the mapped form of addresses Suricata reports as dotted
     * quads. `SuricataCorrelator::address()` does the same two steps for the
     * same reason; it is private there, so this repeats them rather than
     * widening that class's surface for one caller.
     */
    private function canonicalAddress(string $value): string
    {
        $unmapped = $this->sockets->unmapIpv4($value);
        $binary = @inet_pton($unmapped);

        if ($binary === false) {
            return $unmapped;
        }

        $canonical = @inet_ntop($binary);

        return $canonical === false ? $unmapped : $canonical;
    }

    private function port(mixed $value): ?int
    {
        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            return null;
        }

        $port = (int) $value;

        return $port > 0 && $port <= 65535 ? $port : null;
    }

    private function intOrNull(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && ctype_digit($value)) {
            return (int) $value;
        }

        return null;
    }

    /**
     * What is left of a name once the address in front of it is removed.
     *
     * Returns null when the name is not reverse-shaped at all, an empty string
     * when it is nothing but a reverse lookup, and otherwise the part that is
     * not the address.
     *
     * Three shapes have to be told apart, and a boolean cannot do it:
     *
     *   138.77.249.66.in-addr.arpa      a PTR lookup, nothing else in it
     *   2.0.0.127.zen.spamhaus.org      a blocklist lookup: an address in
     *                                   front of an ordinary zone
     *   1.2.3.4.MFRGGZDF….exfil.tld     a payload in front of an ordinary
     *                                   zone, with an address bolted on
     *
     * The first must be exempt: an address with no PTR record answers
     * NXDOMAIN, so anything resolving addresses in bulk emits exactly what the
     * DGA rules key on. The second must be exempt for the same reason — not
     * listed is also NXDOMAIN, and a mail server makes hundreds an hour. The
     * third must not be, and a boolean predicate exempted it, because the only
     * thing it looked at was the digits in front.
     *
     * That was not a hypothetical gap. Both rule files skipped a name of this
     * shape past every counter they own — distinct names, longest label,
     * payload bytes, carrier types — so four cheap digit labels bought
     * invisibility from DNS-001, DNS-002 and DNS-011 through DNS-013 at once.
     * The docblock on the tunnelling side asserted the name "stays visible to
     * DNS-011 and DNS-012 the moment the attacker lengthens a label"; it did
     * not, because the skip came first.
     *
     * Removing the address instead of the name resolves all three: the PTR
     * lookup reduces to nothing and is dropped, the blocklist lookup reduces to
     * its zone and so collapses to one repeated name however many addresses are
     * checked, and the tunnel reduces to its payload and is judged on it.
     *
     * What it still costs: a channel whose payload is *entirely* leading groups
     * of one to three decimal digits is dropped. That is about one byte carried
     * per four bytes of name, four times worse than base32, and lengthening any
     * label to claw it back leaves the digits-only shape and restores
     * visibility — this time for real, since the name is now judged rather than
     * skipped. Hexadecimal is deliberately not accepted, so a hex payload does
     * not qualify.
     */
    public static function reverseLookupRemainder(string $name): ?string
    {
        foreach (['.in-addr.arpa', '.ip6.arpa'] as $suffix) {
            if (str_ends_with($name, $suffix)) {
                return '';
            }
        }

        $labels = explode('.', $name);
        $numeric = 0;

        foreach ($labels as $label) {
            if ($label === '' || !ctype_digit($label) || strlen($label) > 3) {
                break;
            }

            $numeric++;
        }

        if ($numeric < 4) {
            return null;
        }

        return implode('.', array_slice($labels, $numeric));
    }

    /**
     * Whether a name is reverse-shaped: an address, or an address in front of
     * something else.
     *
     * Not a skip on its own — see reverseLookupRemainder(), which is what
     * callers should use to decide what to judge. This exists for the question
     * "is there an address in front of this", and answers only that.
     */
    public static function isReverseLookupName(string $name): bool
    {
        return self::reverseLookupRemainder($name) !== null;
    }
}
