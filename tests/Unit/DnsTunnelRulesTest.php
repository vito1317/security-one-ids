<?php

namespace Tests\Unit;

use App\Services\Network\DnsEventNormalizer;
use App\Services\Network\DnsTunnelRules;
use Tests\TestCase;

/**
 * DNS tunnelling rules, proved in both directions.
 *
 * Both directions, because either one alone is worthless. A rule that fires on
 * a synthetic tunnel and also on this host's ordinary traffic gets switched off
 * within a day; a rule that is silent on real traffic and also silent on a
 * tunnel is worse than no rule at all, because the coverage still appears on
 * the list. So every threshold here is tested from underneath as well as from
 * above, and the last test replays this host's whole real DNS corpus through
 * the rules and requires nothing at all.
 *
 * The synthetic positives are built by mutating a real query row, so that only
 * the name and record type are invented and every other field (the flow, the
 * ports, the timestamp shape) stays exactly as Suricata wrote it. The controls
 * are the shapes that are legitimately tunnel-shaped and must not fire: a busy
 * CDN, a dual-stack burst of brand new names, a mail server's DNS blocklist
 * sweep, a reverse-DNS sweep, and a cloud antivirus hash lookup.
 *
 * Measured evidence recorded at the time of writing, from the run below:
 *   33,458 real dns rows (17,054 queries) replayed as 138 consecutive 30 second
 *   cycles and again as one batch, 0 findings from any rule at either width,
 *   including the real TXT queries in the corpus. The corpus grows while the
 *   logger runs, so that count is a floor rather than a fixed figure.
 */
class DnsTunnelRulesTest extends TestCase
{
    /** A real AAAA query. Every synthetic name in this file is this row with the name changed. */
    private const QUERY_GITHUB = '{"timestamp":"2026-08-28T23:05:29.807382+0800","flow_id":371385289636133,"event_type":"dns","src_ip":"192.168.1.114","src_port":43489,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":30044,"rrname":"api.github.com","rrtype":"AAAA","tx_id":1,"opcode":0}}';

    /**
     * The only TXT query in the corpus, and it is this host's own PowerDNS
     * asking whether its version is still supported. The module brief recorded
     * TXT as never seen here and therefore inherently suspicious; taken
     * literally that fires on the security product's own DNS server, on a
     * schedule, forever.
     */
    private const QUERY_TXT_POWERDNS = '{"timestamp":"2026-08-28T23:24:36.843044+0800","flow_id":1369047600752754,"event_type":"dns","src_ip":"192.168.1.114","src_port":48196,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":11420,"rrname":"auth-4.8.5.security-status.secpoll.powerdns.com","rrtype":"TXT","tx_id":0,"opcode":0}}';

    /** Its answer. The same lookup, logged a second time. */
    private const ANSWER_TXT_POWERDNS = '{"timestamp":"2026-08-28T23:24:37.607735+0800","flow_id":1369047600752754,"event_type":"dns","src_ip":"192.168.1.114","src_port":48196,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":11420,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"auth-4.8.5.security-status.secpoll.powerdns.com","rrtype":"TXT","rcode":"NOERROR","answers":[{"rrname":"auth-4.8.5.security-status.secpoll.powerdns.com","rrtype":"TXT","ttl":59,"rdata":"3 Unsupported release (EOL)"}],"grouped":{"TXT":["3 Unsupported release (EOL)"]}}}';

    /**
     * The real query holding the longest label in the corpus, 22 bytes, and the
     * highest leftmost-label entropy in it at 3.88 bits. It is a connectivity
     * probe. Published DGA families sit at 3.5 to 4.2 bits, which is why no
     * rule in this file uses entropy.
     */
    private const QUERY_LONGEST_REAL_LABEL = '{"timestamp":"2026-08-28T23:08:59.765990+0800","flow_id":1038105406995138,"event_type":"dns","src_ip":"192.168.1.114","src_port":53194,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":2358,"rrname":"no-such-host-abc123xyz.invalid","rrtype":"A","tx_id":0,"opcode":0}}';

    /** A real single-label Docker service name: a query with no parent to tunnel to. */
    private const QUERY_SINGLE_LABEL = '{"timestamp":"2026-08-28T23:06:15.404963+0800","flow_id":2020778053971253,"event_type":"dns","src_ip":"192.168.1.114","src_port":36505,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":32507,"rrname":"nginx-proxy","rrtype":"A","tx_id":0,"opcode":0}}';

    private const LIVE_LOG = '/var/log/suricata/eve.json';

    private DnsEventNormalizer $normalizer;
    private DnsTunnelRules $rules;

    protected function setUp(): void
    {
        parent::setUp();

        $this->normalizer = new DnsEventNormalizer();
        $this->rules = new DnsTunnelRules();
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    private function event(string $line): array
    {
        $event = $this->normalizer->normalizeLine($line);

        $this->assertIsArray($event, 'a real log line must normalise');

        return $event;
    }

    /**
     * A real query row with the name, record type and instant replaced, so that
     * nothing else about the event is invented.
     */
    private function query(string $name, string $rrtype = 'A', float $offset = 0.0): array
    {
        $row = json_decode(self::QUERY_GITHUB, true);
        $row['dns']['rrname'] = $name;
        $row['dns']['rrtype'] = $rrtype;

        $base = 1787929529.807382 + $offset;
        $row['timestamp'] = gmdate('Y-m-d\TH:i:s', (int) $base + 8 * 3600)
            . '.' . sprintf('%06d', (int) round(($base - floor($base)) * 1000000)) . '+0800';

        $event = $this->normalizer->normalize($row);

        $this->assertIsArray($event, "the synthetic row for {$name} must normalise");

        return $event;
    }

    /**
     * Deterministic base32-ish payload, the shape a tunnelling client's labels
     * have. Derived from a hash so that repeated chunks are genuinely distinct:
     * the first version of this helper used a small linear congruential
     * generator and its low bits repeated with a period of 32, so every "chunk"
     * came out identical, the group collapsed to one distinct name and DNS-013
     * silently did not fire. The test passed the negative direction and proved
     * nothing.
     */
    private function payload(int $index, int $length): string
    {
        $alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
        $bytes = hash('sha256', 'chunk' . $index, true) . hash('sha256', 'more' . $index, true);
        $out = '';

        for ($i = 0; $i < $length; $i++) {
            $out .= $alphabet[ord($bytes[$i % strlen($bytes)]) % 32];
        }

        return $out;
    }

    /** @param array<int, array> $events */
    private function rulesByName(array $events): array
    {
        $byRule = [];

        foreach ($this->rules->evaluateBatch($events)['findings'] as $hit) {
            foreach ($hit['findings'] as $finding) {
                $byRule[$finding['rule']][] = $finding;
            }
        }

        return $byRule;
    }

    /* ------------------------------------------------------------------ */
    /* DNS-010, the carrier record types                                   */
    /* ------------------------------------------------------------------ */

    /**
     * The measured baseline for TXT on this host is 1 query in 11,288 and that
     * one query is ours. An "any TXT is out of baseline" rule would have fired
     * on our own PowerDNS every time it ran its version check.
     */
    public function test_the_hosts_own_powerdns_version_check_is_not_a_tunnel(): void
    {
        $this->assertSame([], $this->rules->evaluate($this->event(self::QUERY_TXT_POWERDNS)));

        // Matched loosely on the version, because auth-4.8.5 becomes auth-4.9.0
        // at the next upgrade and an exact-string exemption would start
        // alerting then without anybody touching the rule.
        $this->assertSame([], $this->rules->evaluate($this->query('auth-4.9.0.security-status.secpoll.powerdns.com', 'TXT')));

        // The exemption leaves no label free to encode a payload into, so it
        // cannot be used as a bypass.
        $smuggled = $this->rules->evaluate($this->query(
            $this->payload(1, 48) . '.auth-4.8.5.security-status.secpoll.powerdns.com',
            'TXT'
        ));

        $this->assertNotSame([], $smuggled);
        $this->assertSame('DNS-010', $smuggled[0]['rule']);
    }

    public function test_a_txt_query_is_low_and_a_null_query_is_higher(): void
    {
        $txt = $this->rules->evaluate($this->query('data.exfil.example.com', 'TXT'));

        $this->assertCount(1, $txt);
        $this->assertSame('DNS-010', $txt[0]['rule']);

        // Low on purpose. TXT's measured zero here is a fact about a host that
        // sends no mail: SPF, DKIM, DMARC and ACME dns-01 are all TXT lookups,
        // so one TXT query is not an incident anywhere. It corroborates.
        $this->assertSame('low', $txt[0]['severity']);
        $this->assertSame('T1071.004', $txt[0]['mitre']);
        $this->assertStringContainsString('11,288', $txt[0]['reason'], 'the measurement must be in the reason');

        // NULL is one step higher because, unlike TXT, it has no legitimate
        // modern use to be confused with: no resolver library asks for it, and
        // the tools that do ask because it accepts arbitrary bytes.
        $null = $this->rules->evaluate($this->query('data.exfil.example.com', 'NULL'));

        $this->assertCount(1, $null);
        $this->assertSame('medium', $null[0]['severity']);

        // The record types this host actually resolves with are never carriers.
        foreach (['A', 'AAAA', 'HTTPS', 'NS', 'SOA', 'CNAME', 'MX'] as $rrtype) {
            $this->assertSame(
                [],
                $this->rules->evaluate($this->query('api.github.com', $rrtype)),
                "{$rrtype} must not be treated as a carrier"
            );
        }
    }

    /**
     * The corpus is 11,288 queries against 11,234 answers: one lookup logged
     * twice, with the same name, type and on-wire id. Judging both would double
     * every finding in this file.
     */
    public function test_an_answer_is_not_judged_a_second_time(): void
    {
        $answer = $this->event(self::ANSWER_TXT_POWERDNS);

        $this->assertSame('dns_answer', $answer['action']);
        $this->assertSame([], $this->rules->evaluate($answer));

        // Not just the exempt one: a tunnelling answer is silent too, because
        // its query already spoke.
        $row = json_decode(self::ANSWER_TXT_POWERDNS, true);
        $row['dns']['rrname'] = $this->payload(2, 48) . '.d.exfil.example.com';
        $tunnelAnswer = $this->normalizer->normalize($row);

        $this->assertIsArray($tunnelAnswer);
        $this->assertSame([], $this->rules->evaluate($tunnelAnswer));

        $query = $this->query($this->payload(2, 48) . '.d.exfil.example.com', 'TXT');
        $this->assertNotSame([], $this->rules->evaluate($query), 'the query half must be the half that speaks');
    }

    /* ------------------------------------------------------------------ */
    /* DNS-011 and DNS-012, payload in the name                            */
    /* ------------------------------------------------------------------ */

    /**
     * Measured: the longest label in 11,288 real queries is 22 bytes, p99 is
     * 14, and nothing real reaches 30. The threshold is 45, which is 2.0 times
     * the observed maximum, and the gap is sized for a family this host does
     * not generate: cloud reputation lookups that put a hex digest in one
     * label, 32 bytes for MD5 and 40 for SHA-1.
     */
    public function test_a_long_label_fires_and_every_real_length_below_it_does_not(): void
    {
        $this->assertSame([], $this->rules->evaluate($this->event(self::QUERY_LONGEST_REAL_LABEL)));
        $this->assertSame([], $this->rules->evaluate($this->event(self::QUERY_SINGLE_LABEL)));

        // Right up to the threshold, silent. One byte over it, high.
        $this->assertSame([], $this->rules->evaluate($this->query($this->payload(3, 44) . '.example.com')));

        $hit = $this->rules->evaluate($this->query($this->payload(3, 45) . '.example.com'));

        $this->assertCount(1, $hit);
        $this->assertSame('DNS-011', $hit[0]['rule']);
        $this->assertSame('high', $hit[0]['severity']);
        $this->assertSame('T1048', $hit[0]['mitre']);
        $this->assertStringContainsString('45 bytes', $hit[0]['reason']);
        $this->assertStringContainsString('22 bytes', $hit[0]['reason'], 'the measurement it is judged against');

        // The two legitimate long-label families the margin exists for.
        $this->assertSame([], $this->rules->evaluate($this->query(md5('sample') . '.hash.cloud-av.example.net')));
        $this->assertSame([], $this->rules->evaluate($this->query(sha1('sample') . '.hash.cloud-av.example.net')));

        // And the evasion the margin costs, stated rather than hidden: a 44
        // byte label is invisible to this rule. It is DNS-013 that catches it.
        $this->assertSame(44, strlen($this->payload(3, 44)));
    }

    /**
     * The other way to pack a name is many ordinary labels, which defeats
     * DNS-011 entirely. Measured, the longest real name here is 47 bytes in 7
     * labels, and the longest legitimate shape in DNS at all, an IPv6 reverse
     * pointer, is 72 bytes by construction.
     */
    public function test_a_long_name_fires_even_when_no_single_label_is_long(): void
    {
        $labels = [];

        for ($i = 0; $i < 6; $i++) {
            $labels[] = $this->payload(10 + $i, 20);
        }

        $name = implode('.', $labels) . '.d.exfil.example.com';

        $this->assertGreaterThanOrEqual(128, strlen($name));
        $this->assertLessThan(45, max(array_map('strlen', explode('.', $name))), 'no label may be long enough for DNS-011');

        $hit = $this->rules->evaluate($this->query($name));

        $this->assertCount(1, $hit);
        $this->assertSame('DNS-012', $hit[0]['rule']);
        $this->assertSame('medium', $hit[0]['severity']);
        $this->assertStringContainsString('47 bytes', $hit[0]['reason']);

        // An IPv6 reverse pointer is the longest name a normal host emits: 32
        // nibble labels plus ip6.arpa, and it must stay silent.
        $nibbles = implode('.', array_reverse(str_split(str_repeat('20014860', 4))));
        $pointer = $nibbles . '.ip6.arpa';

        $this->assertSame(72, strlen($pointer), '32 nibble labels plus ip6.arpa');
        $this->assertSame([], $this->rules->evaluate($this->query($pointer, 'PTR')));

        // 127 bytes silent, 128 not. The threshold is where it was measured to
        // be, not near it.
        $justUnder = implode('.', [
            $this->payload(20, 20), $this->payload(21, 20), $this->payload(22, 20),
            $this->payload(23, 20), $this->payload(24, 20), $this->payload(25, 10),
        ]) . '.example.com';

        $this->assertSame(127, strlen($justUnder));
        $this->assertSame([], $this->rules->evaluate($this->query($justUnder)));

        $justOver = $justUnder[0] . $justUnder;

        $this->assertSame(128, strlen($justOver));
        $this->assertCount(1, $this->rules->evaluate($this->query($justOver)));
    }

    /* ------------------------------------------------------------------ */
    /* DNS-013, the shape that separates a tunnel from a busy service       */
    /* ------------------------------------------------------------------ */

    /**
     * The positive direction, on the shape iodine and dnscat2 produce: many
     * distinct names under one parent, each asked once, with the payload in the
     * labels and some of it over TXT.
     */
    public function test_a_synthetic_tunnel_fires_every_rule_and_reports_the_group_once(): void
    {
        $events = [];

        for ($i = 0; $i < 60; $i++) {
            $events[] = $this->query(
                $this->payload($i, 48) . '.d.tunnel-c2.example.net',
                $i % 5 === 0 ? 'TXT' : 'A',
                $i * 0.4
            );
        }

        $result = $this->rules->evaluateBatch($events);
        $byRule = [];

        foreach ($result['findings'] as $hit) {
            foreach ($hit['findings'] as $finding) {
                $byRule[$finding['rule']][] = $finding;
            }
        }

        $this->assertArrayHasKey('DNS-010', $byRule);
        $this->assertArrayHasKey('DNS-011', $byRule);
        $this->assertArrayHasKey('DNS-013', $byRule);
        $this->assertCount(12, $byRule['DNS-010'], 'one per TXT query');
        $this->assertCount(60, $byRule['DNS-011'], 'every name carries a 48 byte label');

        // Reported once, not once per grouping depth, and attributed to the most
        // specific parent the evidence supports rather than to example.net.
        $this->assertCount(1, $byRule['DNS-013']);
        $group = $byRule['DNS-013'][0];
        $this->assertStringContainsString('tunnel-c2.example.net', $group['reason']);
        $this->assertStringContainsString('60 distinct names', $group['reason']);
        // The alert states the quantity it actually computes. It previously
        // printed distinct/queries as "N% of them a name asked for once", which
        // is a different statistic: 24 names over 32 queries is a ratio of 0.75
        // while only 16 of those names were asked exactly once.
        $this->assertStringContainsString('a distinct-name ratio of 1.00', $group['reason']);

        // Critical only because something independent corroborates the shape:
        // the carrier record type and the label length are facts the
        // distinct-name count did not already contain.
        $this->assertSame('critical', $group['severity']);
        $this->assertStringContainsString('Corroborated by', $group['reason']);

        $this->assertTrue($result['stats']['basis_for_group_rule']);
        $this->assertSame(60, $result['stats']['queries']);

        // The alert has to point at a real event, and at the first evidence of
        // the channel rather than at whichever row happened to arrive last.
        $groupHit = null;

        foreach ($result['findings'] as $hit) {
            if ($hit['findings'][0]['rule'] === 'DNS-013') {
                $groupHit = $hit;
            }
        }

        $this->assertNotNull($groupHit);
        $this->assertSame('dns_query', $groupHit['event']['action']);
        $this->assertSame($events[0]['dns']['rrname'], $groupHit['event']['dns']['rrname']);
    }

    /**
     * A tunnel under a multi-label public suffix. There is no public suffix list
     * in this project, so the batch is grouped at two labels and at three: at
     * two this is co.uk, which any other co.uk traffic in the batch would
     * dilute, and at three it is the registrable domain. This is the case depth
     * 3 exists for.
     */
    public function test_a_tunnel_under_a_multi_label_suffix_is_attributed_to_the_registrable_domain(): void
    {
        $events = [];

        for ($i = 0; $i < 30; $i++) {
            $events[] = $this->query($this->payload(100 + $i, 30) . '.x.evil.co.uk', 'A', $i * 0.9);
        }

        // Some real co.uk traffic in the same batch, which is what dilutes the
        // depth 2 group.
        for ($i = 0; $i < 200; $i++) {
            $events[] = $this->query('www.bbc.co.uk', $i % 2 ? 'A' : 'AAAA', $i * 0.1);
        }

        $byRule = $this->rulesByName($events);

        $this->assertArrayHasKey('DNS-013', $byRule);
        $this->assertCount(1, $byRule['DNS-013']);
        $this->assertStringContainsString('under evil.co.uk', $byRule['DNS-013'][0]['reason']);
        $this->assertStringNotContainsString('under co.uk', $byRule['DNS-013'][0]['reason']);

        // High, not critical: no carrier type and no label long enough for
        // DNS-011, so nothing independent corroborates the shape.
        $this->assertSame('high', $byRule['DNS-013'][0]['severity']);
    }

    /**
     * The control that matters most, because it is the shape a naive volume
     * rule fires on all day: a busy service. Measured on this host,
     * cybersecureone.com is 5,396 queries over 6 names and github.com is 3,893
     * over 2. High volume, few names, distinct ratio near zero.
     */
    public function test_a_busy_service_resolving_a_few_names_is_not_a_tunnel(): void
    {
        $events = [];

        for ($i = 0; $i < 600; $i++) {
            $events[] = $this->query('e' . ($i % 20) . '.dscb.akamaiedge.net', $i % 2 ? 'A' : 'AAAA', $i * 0.05);
        }

        $this->assertSame([], $this->rulesByName($events));

        // And with more queries than the real busiest parent, the same answer.
        $events = [];

        for ($i = 0; $i < 5400; $i++) {
            $events[] = $this->query(['waf', 'waf-sf', 'waf-japan', 'waf-america', 'waf-frankfurt'][$i % 5]
                . '.cybersecureone.com', $i % 2 ? 'A' : 'AAAA', $i * 0.005);
        }

        $this->assertSame([], $this->rulesByName($events));
    }

    /**
     * Why the ratio threshold is 0.75 and not 0.5. Legitimate resolution here
     * is dual stack: every name is asked for A and again for AAAA (measured
     * 5,672 A queries against 5,537 AAAA), so a burst of brand new names, which
     * is what a browser's first visit to a CDN-sharded page looks like, sits at
     * a ratio of exactly 0.5 with no repetition at all.
     *
     * The same fact bounds what DNS-013 can see, and the bound is deliberate: a
     * tunnel driven through a dual-stack stub resolver also lands near 0.5 and
     * is missed here. It remains visible to DNS-011, which is asserted below so
     * that the gap is a documented trade rather than an unnoticed hole.
     */
    public function test_a_dual_stack_burst_of_brand_new_names_is_not_a_tunnel(): void
    {
        $events = [];

        for ($i = 0; $i < 40; $i++) {
            $name = 'shard' . $i . '-static.cdnprovider.net';
            $events[] = $this->query($name, 'A', $i * 0.1);
            $events[] = $this->query($name, 'AAAA', $i * 0.1 + 0.01);
        }

        $result = $this->rules->evaluateBatch($events);

        $this->assertSame([], $result['findings']);

        // The rule did have a basis here and answered no, which is a different
        // statement from having no basis at all.
        $this->assertTrue($result['stats']['basis_for_group_rule']);

        $ratios = [];

        foreach ($result['groups'] as $group) {
            if ($group['distinct'] >= 24) {
                $ratios[] = round($group['ratio'], 3);
            }
        }

        $this->assertSame([0.5], array_values(array_unique($ratios)), 'dual stack caps the ratio at 0.5');

        // The missed dual-stack tunnel, and what still catches it.
        $tunnel = [];

        for ($i = 0; $i < 40; $i++) {
            $name = $this->payload(200 + $i, 48) . '.d.slow-c2.example.net';
            $tunnel[] = $this->query($name, 'A', $i * 0.1);
            $tunnel[] = $this->query($name, 'AAAA', $i * 0.1 + 0.01);
        }

        $byRule = $this->rulesByName($tunnel);

        $this->assertArrayNotHasKey('DNS-013', $byRule, 'documented blind spot: ratio 0.5');
        $this->assertArrayHasKey('DNS-011', $byRule, 'and the layer that covers it');
    }

    /**
     * The single largest legitimate source of the exact shape DNS-013 keys on,
     * and the reason the reverse-lookup exemption exists: a mail server
     * checking DNS blocklists queries hundreds of distinct names under one
     * parent, each exactly once, at a ratio of 1.0. Measured 0 times in 11,288
     * queries on this host, so nothing real is being suppressed today; the
     * exemption is sized for the customer hosts that do filter mail.
     */
    public function test_a_dns_blocklist_sweep_is_not_a_tunnel(): void
    {
        $events = [];

        for ($i = 0; $i < 300; $i++) {
            $events[] = $this->query(sprintf(
                '%d.%d.%d.%d.zen.spamhaus.org',
                $i % 254 + 1,
                ($i * 7) % 251 + 1,
                ($i * 13) % 241 + 1,
                ($i * 29) % 239 + 1
            ), 'A', $i * 0.05);
        }

        $result = $this->rules->evaluateBatch($events);

        $this->assertSame([], $result['findings']);

        // Excluded, and counted, so the exclusion is visible rather than
        // invisible: an exemption nobody can see is indistinguishable from a
        // bug.
        //
        // The exclusion happens at the depth where the blocklist zone is the
        // parent, because that is where removing the address leaves nothing
        // below it. One depth up the zone is a name the group genuinely did
        // query, so it is judged — as a single name, three hundred addresses
        // notwithstanding. This block used to assert nothing was judged at
        // either depth, which was asserting the old behaviour: skipping a name
        // outright because it had digits in front of it, which is what let a
        // payload hide behind four digit labels.
        $seen = [];

        foreach ($result['groups'] as $group) {
            $seen[$group['depth']] = $group;
        }

        $this->assertSame(0, $seen[3]['distinct'], 'at the zone depth there is nothing left to judge');
        $this->assertGreaterThan(200, $seen[3]['reverse_names'], 'and the addresses checked are counted');
        $this->assertSame(1, $seen[2]['distinct'], 'one depth up, one name: the zone itself');
        $this->assertSame(
            1,
            $seen[2]['judged_queries'],
            'and three hundred addresses against one zone is one query worth of evidence, '
            . 'or the denominator becomes a hiding place'
        );

        // A reverse-DNS sweep is the same shape from the other side.
        $ptr = [];

        for ($i = 0; $i < 200; $i++) {
            $ptr[] = $this->query(sprintf('%d.%d.168.192.in-addr.arpa', $i % 254 + 1, ($i * 3) % 251 + 1), 'PTR', $i * 0.05);
        }

        $this->assertSame([], $this->rulesByName($ptr));
    }

    /**
     * An exemption is a hiding place unless it is taken out of both halves of
     * the ratio.
     *
     * Blocklist queries were originally removed from the distinct-name count
     * only, which left the denominator made of traffic the rule had already
     * decided not to judge: 30 tunnel names beside 300 blocklist lookups under
     * the same parent came out at a ratio of 0.09 and were silently dropped.
     * Now the exempt names leave both halves and the remaining names are judged
     * on their own.
     */
    public function test_a_tunnel_cannot_hide_inside_an_exempt_blocklist_zone(): void
    {
        $events = [];

        for ($i = 0; $i < 300; $i++) {
            $events[] = $this->query(sprintf(
                '%d.%d.%d.%d.zen.spamhaus.org',
                $i % 254 + 1,
                ($i * 7) % 251 + 1,
                ($i * 13) % 241 + 1,
                ($i * 29) % 239 + 1
            ), 'A', $i * 0.05);
        }

        for ($i = 0; $i < 30; $i++) {
            $events[] = $this->query($this->payload(300 + $i, 30) . '.d.zen.spamhaus.org', 'A', 20.0 + $i * 0.2);
        }

        $byRule = $this->rulesByName($events);

        $this->assertArrayHasKey('DNS-013', $byRule);
        $this->assertCount(1, $byRule['DNS-013']);

        // Attributed to the label carrying the channel, not to the registrable
        // domain above it. The one name the blocklist sweep contributes one
        // level up used to be enough to move the alert from
        // d.zen.spamhaus.org to spamhaus.org, which is a different instruction
        // to whoever acts on it.
        $this->assertStringContainsString('zen.spamhaus.org', $byRule['DNS-013'][0]['reason']);
        $this->assertStringContainsString('30 distinct names', $byRule['DNS-013'][0]['reason']);
        $this->assertStringContainsString('from 30 queries', $byRule['DNS-013'][0]['reason']);
        $this->assertStringContainsString(
            'reverse-lookup shaped and excluded',
            $byRule['DNS-013'][0]['reason'],
            'the exclusion has to be visible in the alert, or it is indistinguishable from a bug'
        );
    }

    /**
     * Four digit labels must not buy invisibility.
     *
     * The exemption used to skip the whole name: anything with four leading
     * groups of one to three digits reached none of the counters in this file
     * — not the distinct-name count, not the longest label, not the payload
     * byte total, not the carrier types. So an attacker paid eight characters
     * and vanished from every rule here, and from DNS-001 and DNS-002 as well
     * once the DGA rules started sharing the predicate.
     *
     * The address is now removed and what is left is judged, so the payload is
     * still there to be seen.
     */
    public function test_a_payload_cannot_hide_behind_four_digit_labels(): void
    {
        $events = [];

        for ($i = 0; $i < 30; $i++) {
            $events[] = $this->query(
                sprintf('%d.%d.%d.%d.', $i % 254 + 1, $i % 251 + 1, $i % 241 + 1, $i % 239 + 1)
                . $this->payload(700 + $i, 48) . '.d.exfil.example.net',
                'A',
                $i * 0.2
            );
        }

        $byRule = $this->rulesByName($events);

        $this->assertArrayHasKey('DNS-013', $byRule, 'the distinct-name shape survives the address in front');
        $this->assertArrayHasKey('DNS-011', $byRule, 'and so does the label too long to be a hostname');
        $this->assertStringContainsString('exfil.example.net', $byRule['DNS-013'][0]['reason']);
    }

    /**
     * The exemption has to be narrow or it is a bypass. Only decimal digits
     * count, so a payload encoded as short hexadecimal labels is not exempt.
     */
    public function test_the_reverse_lookup_exemption_does_not_accept_hex_labels(): void
    {
        $this->assertTrue($this->rules->isReverseLookupName('4.3.2.1.zen.spamhaus.org'));
        $this->assertTrue($this->rules->isReverseLookupName('1.0.0.127.in-addr.arpa'));
        $this->assertFalse($this->rules->isReverseLookupName('a1.b2.c3.d4.evil.example.com'));
        $this->assertFalse($this->rules->isReverseLookupName('1234.2.3.4.evil.example.com'), 'four digits is not an octet');
        $this->assertFalse($this->rules->isReverseLookupName('1.2.3.evil.example.com'), 'three groups is not an address');

        $events = [];

        for ($i = 0; $i < 30; $i++) {
            $events[] = $this->query(sprintf(
                '%02x.%02x.%02x.%02x.d.hex-c2.example.net',
                $i,
                ($i * 7) % 256,
                ($i * 13) % 256,
                ($i * 29) % 256
            ), 'A', $i * 0.2);
        }

        $byRule = $this->rulesByName($events);

        $this->assertArrayHasKey('DNS-013', $byRule, 'hex labels must not buy an exemption');
    }

    /**
     * A residual false positive, kept rather than exempted, and graded for it.
     *
     * Cloud antivirus and reputation services encode a file digest into the
     * name, which is genuinely DNS used as a data channel and genuinely
     * legitimate. It cannot be told from a tunnel by shape, and an allowlist of
     * such vendors would be a list I cannot measure on this host, so it fires at
     * 'high' rather than 'critical': look at this, do not act on it. This test
     * exists so the behaviour is a recorded decision instead of a surprise.
     */
    public function test_a_cloud_antivirus_hash_lookup_fires_at_high_and_is_a_known_residual(): void
    {
        $events = [];

        for ($i = 0; $i < 30; $i++) {
            $events[] = $this->query(sha1('file' . $i) . '.hash.avqs.example-av.com', 'A', $i * 0.3);
        }

        $byRule = $this->rulesByName($events);

        $this->assertSame(['DNS-013'], array_keys($byRule), 'a 40 byte SHA-1 label stays under DNS-011');
        $this->assertSame('high', $byRule['DNS-013'][0]['severity']);
    }

    /**
     * "We did not see" is not "it did not happen". Measured on this host the
     * busiest parent reaches 5 distinct names in a 30 second cycle against a
     * gate of 24, so DNS-013 is normally silent for lack of a basis rather than
     * because it looked. A caller reporting coverage has to be able to tell
     * those apart, which is what this flag is for.
     */
    public function test_a_batch_with_no_basis_to_judge_says_so_rather_than_reporting_clean(): void
    {
        $small = [
            $this->query('api.github.com', 'A', 0.0),
            $this->query('waf.cybersecureone.com', 'A', 0.1),
        ];

        $result = $this->rules->evaluateBatch($small);

        $this->assertSame([], $result['findings']);
        $this->assertFalse($result['stats']['basis_for_group_rule']);
        $this->assertSame(0, $result['stats']['groups_at_distinct_gate']);

        $empty = $this->rules->evaluateBatch([]);

        $this->assertSame([], $empty['findings']);
        $this->assertFalse($empty['stats']['basis_for_group_rule']);
        $this->assertSame(0, $empty['stats']['queries']);
        $this->assertNull($empty['stats']['window_seconds'], 'no events, so no window was observed');

        // A caller that hands these rules the wrong stream should be able to
        // see that it did, rather than reading an empty finding list as a quiet
        // host.
        $wrong = $this->rules->evaluateBatch([
            ['action' => 'net_connect', 'network' => ['remote_address' => '8.8.8.8', 'remote_port' => 53]],
        ]);

        $this->assertSame(1, $wrong['stats']['not_dns']);
        $this->assertSame(0, $wrong['stats']['queries']);
    }

    /* ------------------------------------------------------------------ */
    /* The other direction: this host's real traffic                        */
    /* ------------------------------------------------------------------ */

    /**
     * Replay every DNS event this host has logged, both as the 30 second
     * batches the collect cycle actually produces (EDR_INTERVAL in
     * security-one-watchdog.sh) and as one whole-corpus batch, and require that
     * no rule fires at all.
     *
     * Both widths matter. The per-cycle replay is what will really happen. The
     * single-batch replay is the harder test: every distinct-name count in it is
     * accumulated over 46 minutes instead of 30 seconds, so if a threshold were
     * set too close to this host's behaviour it would show up there first.
     *
     * Recorded from the run at the time of writing: 33,458 rows over 4,112
     * seconds, 138 cycles, 0 findings at either width, and the closest any real
     * parent came to the DNS-013 gates was 6 distinct names (against 24) at a
     * distinct ratio of 0.0011 (against 0.75).
     *
     * Skipped rather than failed when the log cannot be read or DNS logging is
     * off, because "we could not look" is not the same finding as "there was
     * nothing there". The corpus is also finite in a way worth stating: as
     * DnsEventNormalizer records, the seven rotated generations hold 0 dns rows,
     * so this is the whole DNS history of this host and it restarts at every
     * rotation.
     */
    public function test_it_is_silent_on_this_hosts_real_dns_traffic(): void
    {
        $lines = $this->liveDnsLines();

        if (count($lines) < 5000) {
            $this->markTestSkipped(
                'not enough live DNS telemetry to replay: ' . count($lines) . ' rows in the tail of ' . self::LIVE_LOG
            );
        }

        $events = [];

        foreach ($lines as $line) {
            $event = $this->normalizer->normalizeLine($line);

            if ($event !== null) {
                $events[] = $event;
            }
        }

        $this->assertSame(count($lines), count($events), 'every real row must normalise');
        $this->assertGreaterThan(20000, count($events), 'the negative direction needs a real corpus behind it');

        // Every real event through the per-event rules.
        $perEvent = [];

        foreach ($events as $event) {
            foreach ($this->rules->evaluate($event) as $finding) {
                $perEvent[] = $finding['rule'] . ' ' . $finding['reason'];
            }
        }

        $this->assertSame([], $perEvent, 'DNS-010 to DNS-012 must be silent on real traffic');

        // The real cycle: 30 second batches, which at the measured 8.12 rows a
        // second is roughly 244 rows each.
        $cycles = [];
        $start = null;

        foreach ($events as $event) {
            $time = (float) $event['network']['event_time_wall'];
            $start = $start === null ? $time : min($start, $time);
        }

        foreach ($events as $event) {
            $cycles[(int) floor(((float) $event['network']['event_time_wall'] - $start) / 30)][] = $event;
        }

        $this->assertGreaterThan(30, count($cycles), 'the corpus must span enough cycles to be worth replaying');

        $findings = [];
        $withBasis = 0;

        foreach ($cycles as $cycle) {
            $result = $this->rules->evaluateBatch($cycle);
            $withBasis += $result['stats']['basis_for_group_rule'] ? 1 : 0;

            foreach ($result['findings'] as $hit) {
                foreach ($hit['findings'] as $finding) {
                    $findings[] = $finding['rule'] . ': ' . $finding['reason'];
                }
            }
        }

        $this->assertSame([], $findings, 'no rule may fire on any real 30 second cycle');

        // And the honest half of that result: on this host no cycle even
        // reaches the point where DNS-013 could return a verdict, so its
        // silence here is not evidence that there is no tunnel. Only the
        // per-event rules are actually being exercised by real traffic.
        $this->assertSame(0, $withBasis);

        // The whole corpus as one batch, where every count is accumulated over
        // the full span rather than 30 seconds.
        $whole = $this->rules->evaluateBatch($events);

        $this->assertSame([], $whole['findings'], 'no rule may fire over the whole corpus either');
        $this->assertSame(0, $whole['stats']['groups_at_distinct_gate']);

        // The margin, asserted rather than described, so that a threshold
        // edited without re-measuring fails here.
        $worstDistinct = 0;
        $worstRatio = 0.0;
        $worstPayload = 0;

        foreach ($whole['groups'] as $group) {
            $worstDistinct = max($worstDistinct, $group['distinct']);
            $worstPayload = max($worstPayload, $group['payload_bytes']);

            if ($group['queries'] >= 40) {
                $worstRatio = max($worstRatio, $group['ratio']);
            }
        }

        $this->assertLessThanOrEqual(8, $worstDistinct, 'measured 6 distinct names under any parent');
        $this->assertLessThan(0.2, $worstRatio, 'measured 0.089 over the corpus, 0.125 in a 60 second window');
        $this->assertLessThanOrEqual(64, $worstPayload, 'measured 42 bytes of unique sub-domain data');
    }

    /**
     * Raw dns lines from the tail of the live log.
     *
     * A 192 MB tail rather than the 16 MB the normaliser's test uses, measured:
     * dns rows are sparse in this file (16 MB holds 4,809 of them, 64 MB holds
     * 19,753, 192 MB holds all 29,895), and this test's whole point is the size
     * of the corpus it is quiet on.
     *
     * @return array<int, string>
     */
    private function liveDnsLines(int $tailBytes = 192 * 1024 * 1024, int $cap = 40000): array
    {
        if (!is_readable(self::LIVE_LOG)) {
            return [];
        }

        $size = (int) @filesize(self::LIVE_LOG);
        $handle = @fopen(self::LIVE_LOG, 'rb');

        if ($handle === false) {
            return [];
        }

        if ($size > $tailBytes) {
            fseek($handle, $size - $tailBytes);
            // Discard the partial line the seek landed inside.
            fgets($handle);
        }

        $lines = [];

        while (count($lines) < $cap && ($line = fgets($handle)) !== false) {
            if (str_contains($line, '"event_type":"dns"')) {
                $lines[] = $line;
            }
        }

        fclose($handle);

        return $lines;
    }
}
