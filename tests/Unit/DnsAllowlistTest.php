<?php

namespace Tests\Unit;

use App\Services\Network\DnsAllowlist;
use App\Services\Network\DnsEventNormalizer;
use Tests\TestCase;

/**
 * Internal-domain recognition and allowlist management for the DNS module.
 *
 * Both directions are proved for everything that makes a judgement, because a
 * rule that cannot fire is worse than no rule: each detector-facing behaviour
 * has a synthetic positive and a check that it is silent on this host's real
 * traffic. The last two tests replay the live log for the second half.
 *
 * The suffix-matching tests are synthetic on purpose, and the reason is
 * measured rather than stylistic. Of the 42 distinct names this host queried in
 * the 47-minute corpus, there are 0 pairs where one name contains another as a
 * non-suffix substring, so a substring matcher would have produced identical
 * output on all 23,234 real rows. The bug this test exists to catch is
 * invisible in real traffic right up to the moment somebody uses it, which is
 * why `notexample.com` and `example.com.evil.net` have to be written by hand.
 *
 * Real log lines are copied byte for byte out of /var/log/suricata/eve.json so
 * the classification is exercised through the shape the normaliser actually
 * produces, not through a hand-built array that agrees with my assumptions.
 */
class DnsAllowlistTest extends TestCase
{
    /** Real queries. host.docker.internal and nginx-proxy are the two shapes
     * that make internal recognition necessary: 362 and 128 rows respectively,
     * and between them 245 of the 255 NXDOMAIN rows in the corpus. */
    private const QUERY_DOCKER_INTERNAL = '{"timestamp":"2026-08-28T23:05:33.644943+0800","flow_id":1644109239592472,"event_type":"dns","src_ip":"192.168.1.114","src_port":34204,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":38508,"rrname":"host.docker.internal","rrtype":"A","tx_id":0,"opcode":0}}';
    private const QUERY_SINGLE_LABEL = '{"timestamp":"2026-08-28T23:06:15.404963+0800","flow_id":2020778053971253,"event_type":"dns","src_ip":"192.168.1.114","src_port":36505,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":32507,"rrname":"nginx-proxy","rrtype":"A","tx_id":0,"opcode":0}}';

    /** A real query for the agent's own control plane: 9,892 rows, the busiest
     * name on the host, and the most defensible allowlist entry there is. */
    private const QUERY_CONTROL_PLANE = '{"timestamp":"2026-08-28T23:05:29.669175+0800","flow_id":340812526310459,"event_type":"dns","src_ip":"192.168.1.114","src_port":32941,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":22601,"rrname":"waf.cybersecureone.com","rrtype":"A","tx_id":0,"opcode":0}}';

    /** A real query under a dynamic-DNS parent, 54 rows. This is why
     * REGISTRY_SUFFIXES exists: somebody tuning this noise would write the
     * parent, and the parent is where commodity C2 lives. */
    private const QUERY_DYNDNS = '{"timestamp":"2026-08-28T23:10:01.483960+0800","flow_id":389745284378325,"event_type":"dns","src_ip":"192.168.1.114","src_port":39984,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":19843,"rrname":"gpg-gtb.dyndns.org","rrtype":"A","tx_id":0,"opcode":0}}';

    private const LIVE_LOG = '/var/log/suricata/eve.json';

    private DnsAllowlist $allowlist;
    private DnsEventNormalizer $normalizer;

    protected function setUp(): void
    {
        parent::setUp();

        $this->allowlist = new DnsAllowlist();
        $this->normalizer = new DnsEventNormalizer();
    }

    private function event(string $line): array
    {
        $event = $this->normalizer->normalizeLine($line);

        $this->assertIsArray($event, 'a real log line must normalise');

        return $event;
    }

    /**
     * The security-relevant half of this class, and the half real traffic
     * cannot check.
     */
    public function test_a_suffix_entry_matches_the_apex_and_what_is_under_it(): void
    {
        $this->allowlist->setAllowlist(['example.com']);

        foreach (['example.com', 'api.example.com', 'deep.api.example.com'] as $name) {
            $verdict = $this->allowlist->classifyName($name, []);

            $this->assertSame('allowed', $verdict['verdict'], "{$name} is under the entry");
            $this->assertSame('example.com', $verdict['entry']);
        }
    }

    public function test_a_suffix_entry_does_not_match_a_name_that_merely_contains_it(): void
    {
        $this->allowlist->setAllowlist(['example.com']);

        // The three cases in order of how much they cost if wrong. The middle
        // one is the live bypass: an attacker who can read the allowlist
        // registers example.com.evil.net and owns its authoritative server, so
        // a substring matcher hands them a tunnel that is excused by policy.
        foreach (['notexample.com', 'example.com.evil.net', 'evil.net', 'anotherexample.com'] as $name) {
            $verdict = $this->allowlist->classifyName($name, []);

            $this->assertSame('evaluate', $verdict['verdict'], "{$name} must not be excused");
            $this->assertSame('no_match', $verdict['reason']);
            $this->assertNull($verdict['entry']);
        }

        // Stated as an assertion rather than a comment, because this is the
        // whole reason the cases above are hand-written: the naive matcher
        // disagrees only on names this host has never queried.
        $this->assertTrue(
            str_contains('example.com.evil.net', 'example.com'),
            'a substring matcher would excuse the bypass this one refuses'
        );
    }

    public function test_an_entry_is_normalised_the_way_an_rrname_is(): void
    {
        // An entry is typed by a human, so it arrives shouted, dotted and
        // wildcarded. Measured, 0 of 23,234 rrnames needed case or
        // trailing-dot correction, so if the entry is not normalised the same
        // way the mismatch is silent and total.
        $this->allowlist->setAllowlist(['Example.COM.', '*.github.com']);

        $this->assertSame(['example.com', 'github.com'], $this->allowlist->entries());
        $this->assertSame('allowed', $this->allowlist->classifyName('API.Example.Com.', [])['verdict']);

        // A leading `*.` includes the apex, which is a real difference and not a
        // hypothetical one: 10 of the 8,342 github.com rows in the corpus are
        // the apex itself.
        $this->assertSame('allowed', $this->allowlist->classifyName('github.com', [])['verdict']);
        $this->assertSame('allowed', $this->allowlist->classifyName('api.github.com', [])['verdict']);

        $notes = array_column($this->allowlist->notes(), 'note', 'entry');
        $this->assertSame('wildcard_normalised', $notes['github.com'] ?? null);
    }

    /**
     * Every refusal, with the entry proved absent from the table afterwards.
     *
     * The point is not the reason strings, it is that a refused entry is not
     * stored. EdrExclusionSuggester's failure was an exclusion that was stored,
     * displayed as applied, and could never match.
     */
    public function test_an_entry_that_cannot_work_is_refused_rather_than_stored(): void
    {
        $this->allowlist->setAllowlist([
            '*',                                    // suppresses 100% of 23,234 rows
            '.',
            'com',                                  // suppresses 93.96% of them
            'tw',
            'dyndns.org',                            // anyone can obtain a name here
            'amazonaws.com',
            '*example.com',                           // the notexample.com bug, blessed
            'ex*.com',
            'a b.com',
            str_repeat('x', 64) . '.example.com',     // label over 63 bytes
            str_repeat('abcdefgh.', 30) . 'com',      // name over 253 bytes
            '',
            42,
            ['note' => 'no suffix here'],
            ['suffix' => 'scoped.example.com', 'rules' => ['', '  ']],
            'good.example.com',                       // the one that survives
        ]);

        $this->assertSame(['good.example.com'], $this->allowlist->entries());

        $reasons = array_column($this->allowlist->refused(), 'reason', 'entry');

        $this->assertSame('match_everything', $reasons['*']);
        $this->assertSame('match_everything', $reasons['.']);
        $this->assertSame('single_label', $reasons['com']);
        $this->assertSame('single_label', $reasons['tw']);
        $this->assertSame('registry_suffix', $reasons['dyndns.org']);
        $this->assertSame('registry_suffix', $reasons['amazonaws.com']);
        $this->assertSame('unsupported_wildcard', $reasons['*example.com']);
        $this->assertSame('unsupported_wildcard', $reasons['ex*.com']);
        $this->assertSame('invalid_character', $reasons['a b.com']);
        $this->assertSame('too_long', $reasons[str_repeat('x', 64) . '.example.com']);
        $this->assertSame('too_long', $reasons[str_repeat('abcdefgh.', 30) . 'com']);
        $this->assertSame('empty', $reasons['']);
        $this->assertSame('not_a_domain', $reasons['42']);
        $this->assertSame('empty_rule_scope', $reasons['scoped.example.com']);

        // A refusal nobody can read is the same failure with a different field,
        // so every one carries a message for whoever approved the entry.
        foreach ($this->allowlist->refused() as $refusal) {
            $this->assertNotSame('', $refusal['message']);
            $this->assertStringContainsString('not applied', $refusal['message']);
        }

        // And none of them can suppress anything.
        $this->assertSame('evaluate', $this->allowlist->classifyName('anything.at.all.com', [])['verdict']);
        $this->assertSame('allowed', $this->allowlist->classifyName('good.example.com', [])['verdict']);
    }

    public function test_the_entry_ceiling_refuses_the_overflow_rather_than_truncating_it(): void
    {
        $entries = [];

        for ($i = 0; $i < 520; $i++) {
            $entries[] = 'host' . $i . '.example.com';
        }

        $this->allowlist->setAllowlist($entries);

        $this->assertCount(500, $this->allowlist->entries());
        $refused = $this->allowlist->refused();
        $this->assertCount(20, $refused);
        $this->assertSame('entry_limit', $refused[0]['reason']);

        // Truncating silently would leave 20 entries that the Hub shows as
        // applied and that can never match.
        $this->assertSame('evaluate', $this->allowlist->classifyName('host519.example.com', [])['verdict']);
    }

    public function test_a_duplicated_or_shadowed_entry_is_applied_but_reported(): void
    {
        // Order reversed on purpose: the shadow check used to run inside the
        // install loop, where ['api.github.com', 'github.com'] produced no note
        // and the reverse order did, making the report depend on how the Hub
        // serialised the list.
        $this->allowlist->setAllowlist(['api.github.com', 'github.com', 'github.com']);

        $this->assertSame(['api.github.com', 'github.com'], $this->allowlist->entries());

        $notes = [];

        foreach ($this->allowlist->notes() as $note) {
            $notes[$note['entry']][] = $note['note'];
        }

        $this->assertContains('shadowed', $notes['api.github.com'] ?? []);
        $this->assertContains('duplicate', $notes['github.com'] ?? []);
    }

    public function test_reserved_internal_suffixes_are_recognised_without_configuration(): void
    {
        // A fresh instance: nothing configured, nothing discovered.
        foreach ([
            'host.docker.internal' => 'internal',
            'printer.local' => 'local',
            'nas.lan' => 'lan',
            'gw.home.arpa' => 'home.arpa',
            'db.localdomain' => 'localdomain',
            'no-such-host-abc123xyz.invalid' => 'invalid',
            'fixture.test' => 'test',
        ] as $name => $suffix) {
            $verdict = $this->allowlist->classifyName($name, []);

            $this->assertSame('internal', $verdict['verdict'], "{$name} is internal by namespace");
            $this->assertSame('internal_suffix', $verdict['reason']);
            $this->assertSame($suffix, $verdict['entry']);
            $this->assertSame('reserved', $verdict['source']);
        }

        // The other direction. A public name that merely looks internal is not,
        // and this is the failure that matters: `internal.example.com` is a
        // name an attacker can register.
        foreach (['internal.example.com', 'local.example.com', 'lan.evil.net'] as $name) {
            $this->assertSame('evaluate', $this->allowlist->classifyName($name, [])['verdict'], $name);
        }
    }

    public function test_a_dotless_name_is_internal_and_a_real_container_query_proves_it(): void
    {
        $verdict = $this->allowlist->classify($this->event(self::QUERY_SINGLE_LABEL));

        $this->assertSame('internal', $verdict['verdict']);
        $this->assertSame('dotless', $verdict['reason']);
        $this->assertSame('nginx-proxy', $verdict['entry']);

        // And the reason it is safe to excuse: nobody can obtain a delegation
        // for a dotless name, so the query cannot reach a server of the
        // attacker's choosing. The docker name is the same argument one level
        // up, and both are real queries on this host.
        $this->assertSame('internal', $this->allowlist->classify($this->event(self::QUERY_DOCKER_INTERNAL))['verdict']);

        // Not excused: a real public name from the same log.
        $this->assertSame('evaluate', $this->allowlist->classify($this->event(self::QUERY_CONTROL_PLANE))['verdict']);
        $this->assertSame('evaluate', $this->allowlist->classify($this->event(self::QUERY_DYNDNS))['verdict']);
    }

    /**
     * The two exclusions from the reserved set, both deliberate.
     *
     * Asserted rather than commented so that adding either one becomes a test
     * change and therefore a decision.
     */
    public function test_onion_and_the_reverse_zones_are_deliberately_not_internal(): void
    {
        // .onion is non-delegatable and would qualify on the delegation
        // argument, but a .onion name reaching a public resolver IS the
        // finding: something tried to resolve a hidden service without Tor.
        $this->assertSame('evaluate', $this->allowlist->classifyName('facebookcorewwwi.onion', [])['verdict']);

        // The reverse zones are the one place the delegation argument fails:
        // they are delegated in the public DNS to whoever holds the address
        // block, and an ip6.arpa name carries 32 attacker-chosen nibbles.
        $this->assertSame('evaluate', $this->allowlist->classifyName('1.0.0.127.in-addr.arpa', [])['verdict']);
        $this->assertSame(
            'evaluate',
            $this->allowlist->classifyName('0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa', [])['verdict']
        );

        $this->assertSame(
            ['internal', 'local', 'localdomain', 'lan', 'home.arpa', 'localhost', 'invalid', 'test', 'example'],
            DnsAllowlist::RESERVED_INTERNAL_SUFFIXES,
            'changing this set is a decision, not a tidy-up'
        );
    }

    public function test_a_structurally_anomalous_name_overrides_both_verdicts(): void
    {
        $this->allowlist->setAllowlist(['example.com']);

        // A tunnel puts its payload in the labels to the LEFT of the suffix,
        // which is exactly what an allowlist entry says nothing about.
        $tunnel = str_repeat('7a', 40) . '.example.com';

        $verdict = $this->allowlist->classifyName($tunnel, ['label_too_long']);
        $this->assertSame('evaluate', $verdict['verdict']);
        $this->assertStringStartsWith('anomalous_under_allowlist:', $verdict['reason']);
        $this->assertSame('example.com', $verdict['entry'], 'the overridden entry is still reported');

        // The same override applies under an internal suffix, so a tunnel
        // cannot hide behind the automatic classification either.
        $verdict = $this->allowlist->classifyName('x.docker.internal', ['non_ldh_character']);
        $this->assertSame('evaluate', $verdict['verdict']);
        $this->assertStringStartsWith('anomalous_under_internal:', $verdict['reason']);

        // The other direction, and the reason the flag set is not just
        // "anything flagged": single_label IS the dotless marker, and
        // hyphen_edge is malformedness rather than capacity, so neither
        // overrides. Measured, 0 of 23,234 real rows carried any of the four
        // flags that do.
        $this->assertSame('internal', $this->allowlist->classifyName('nginx-proxy', ['single_label'])['verdict']);
        $this->assertSame('allowed', $this->allowlist->classifyName('-api.example.com', ['hyphen_edge'])['verdict']);
        $this->assertSame('allowed', $this->allowlist->classifyName('api.example.com', [])['verdict']);
    }

    public function test_a_rule_scoped_entry_excuses_that_rule_only(): void
    {
        $this->allowlist->setAllowlist([
            ['suffix' => 'api.github.com', 'rules' => ['DNS-004'], 'note' => 'ticket 4711'],
            'api.notion.com',
        ]);

        $this->assertSame('allowed', $this->allowlist->classifyName('api.github.com', [], 'DNS-004')['verdict']);
        // Case is normalised on both sides, or a lower-case rule id in the Hub
        // payload would silently scope the entry to nothing.
        $this->assertSame('allowed', $this->allowlist->classifyName('api.github.com', [], 'dns-004')['verdict']);

        $this->assertSame('evaluate', $this->allowlist->classifyName('api.github.com', [], 'DNS-001')['verdict']);

        // A caller that named no rule cannot be given the benefit of a scoped
        // entry: that would widen the scope to every rule, so it fails towards
        // detection instead.
        $this->assertSame('evaluate', $this->allowlist->classifyName('api.github.com', [])['verdict']);

        // An unscoped entry is unaffected by any of that.
        $this->assertSame('allowed', $this->allowlist->classifyName('api.notion.com', [], 'DNS-001')['verdict']);
    }

    public function test_an_unreadable_name_or_event_is_never_suppressed(): void
    {
        $this->allowlist->setAllowlist(['example.com']);

        $this->assertSame('no_name', $this->allowlist->classifyName('', [])['reason']);
        $this->assertSame('no_name', $this->allowlist->classifyName('.', [])['reason']);
        $this->assertSame('no_dns_section', $this->allowlist->classify(['action' => 'net_connect'])['reason']);

        // Absence of a readable name is not permission to stay quiet: all of
        // these fall through to evaluation rather than to a suppressing verdict.
        $this->assertSame('evaluate', $this->allowlist->classifyName('', [])['verdict']);
        $this->assertSame('evaluate', $this->allowlist->classify([])['verdict']);
    }

    public function test_discovery_applies_only_the_suffixes_nobody_can_register_under(): void
    {
        $path = sys_get_temp_dir() . '/dns_allowlist_resolv_' . getmypid() . '.conf';
        file_put_contents(
            $path,
            "# generated\nnameserver 127.0.0.53\n"
            . "search lab.internal corp.example.com ~routed.local .\n"
        );

        $result = $this->allowlist->discoverInternalDomains($path);

        $this->assertSame(['lab.internal', 'routed.local'], $result['applied']);
        $this->assertSame(['corp.example.com'], $result['candidates'], 'a public zone needs a human');
        $this->assertSame('search_domain', $result['basis']);

        $verdict = $this->allowlist->classifyName('db.lab.internal', []);
        $this->assertSame('internal', $verdict['verdict']);
        $this->assertSame('discovered', $verdict['source']);

        // The candidate is NOT applied. Names under a public zone can be
        // created by anyone who can create records in it, so allowlisting the
        // whole zone would delete the tunnelling detection for the one zone an
        // insider can write to.
        $this->assertSame('evaluate', $this->allowlist->classifyName('db.corp.example.com', [])['verdict']);

        unlink($path);
    }

    public function test_discovery_says_which_kind_of_nothing_it_found(): void
    {
        // This host's real shape: systemd-resolved writes `search .` when there
        // is no search domain, and the hostname (gx10-dc8a) has no domain part.
        $path = sys_get_temp_dir() . '/dns_allowlist_resolv_empty_' . getmypid() . '.conf';
        file_put_contents($path, "nameserver 8.8.8.8\nsearch .\n");

        $result = $this->allowlist->discoverInternalDomains($path);

        $this->assertSame([], $result['applied']);
        $this->assertSame('no_search_domain', $result['basis'], 'we looked, and there is none');

        // Which is a different finding from not being able to look at all: a
        // container with no resolv.conf mounted returns the same empty arrays.
        $missing = $this->allowlist->discoverInternalDomains($path . '.absent');
        $this->assertSame([], $missing['applied']);
        $this->assertStringStartsWith('unreadable:', $missing['basis']);

        // And on the real file, whatever this host currently has, the basis is
        // always stated rather than implied.
        $live = $this->allowlist->discoverInternalDomains();
        $this->assertContains(
            $live['basis'],
            ['no_search_domain', 'search_domain', 'unreadable:/etc/resolv.conf']
        );

        unlink($path);
    }

    /**
     * The heuristic this class refuses to implement.
     *
     * "A name that only ever resolves into private space is internal" is
     * decided by whoever operates the zone, so an attacker publishes one A
     * record in RFC 1918 space and their own C2 domain is auto-allowlisted.
     * That is DNS rebinding, and it costs them one record. Asserted here so
     * that adding answer-driven discovery breaks a test rather than a customer.
     */
    public function test_an_answer_pointing_into_private_space_does_not_allowlist_anything(): void
    {
        $rebind = '{"timestamp":"2026-08-28T23:05:50.825603+0800","flow_id":1835623357181964,'
            . '"event_type":"dns","src_ip":"192.168.1.114","src_port":38886,"dest_ip":"8.8.8.8",'
            . '"dest_port":53,"proto":"UDP","dns":{"version":2,"type":"answer","id":45074,'
            . '"rrname":"c2.attacker-example.net","rrtype":"A","rcode":"NOERROR","answers":'
            . '[{"rrname":"c2.attacker-example.net","rrtype":"A","ttl":1,"rdata":"192.168.1.114"}],'
            . '"grouped":{"A":["192.168.1.114"]}}}';

        $before = $this->allowlist->internalSuffixes();

        for ($i = 0; $i < 50; $i++) {
            $verdict = $this->allowlist->classify($this->event($rebind));
            $this->assertSame('evaluate', $verdict['verdict']);
        }

        $this->assertSame($before, $this->allowlist->internalSuffixes(), 'answers must teach nothing');
    }

    public function test_coverage_reports_both_ways_an_entry_can_be_wrong(): void
    {
        $this->allowlist->setAllowlist([
            'cybersecureone.com',
            ['suffix' => 'api.github.com', 'rules' => ['DNS-004']],
            'never-queried.example.org',
        ]);

        // Shaped like the real distribution, with the measured row counts.
        $report = $this->allowlist->coverage([
            'waf.cybersecureone.com' => 9892,
            'waf-japan.cybersecureone.com' => 248,
            'api.github.com' => 8332,
            'api.notion.com' => 728,
            'host.docker.internal' => 362,
            'nginx-proxy' => 128,
        ]);

        $this->assertTrue($report['basis']);
        $this->assertSame(19690, $report['rows']);

        // An entry that matches nothing is the EdrExclusionSuggester failure:
        // approved, stored, displayed as applied, inert.
        $this->assertContains('matches_nothing', $report['entries']['never-queried.example.org']['flags']);

        // A rule-scoped entry is credited with its whole reach and flagged,
        // rather than reported as matching nothing, which is what counting it
        // under a null rule would have said.
        $this->assertSame(8332, $report['entries']['api.github.com']['rows']);
        $this->assertContains('rule_scoped', $report['entries']['api.github.com']['flags']);

        // The internal classification is accounted separately, so an operator
        // cannot read their entry's coverage off rows it never suppressed.
        $this->assertSame(362, $report['internal']['internal']['rows']);
        $this->assertSame(128, $report['internal']['(dotless)']['rows']);
        $this->assertSame(10140, $report['entries']['cybersecureone.com']['rows']);

        // And the aggregate, which is the only place "the allowlist has grown
        // to cover everything" is visible. Each entry here is defensible on its
        // own; the total is what an operator has to look at.
        $this->assertGreaterThan(0.9, $report['suppressed_fraction']);
    }

    public function test_a_dominant_entry_is_flagged_but_a_busy_legitimate_one_is_not(): void
    {
        // The measured poles. cybersecureone.com is the agent's own control
        // plane at 46.86% of the stream and must not be flagged, or the flag
        // means nothing; a hypothetical entry covering nearly everything must
        // be. `com` itself cannot be tested here because it is refused before
        // it can be measured, which is the point of the structural refusal.
        $this->allowlist->setAllowlist(['cybersecureone.com', 'github.com']);

        $report = $this->allowlist->coverage([
            'waf.cybersecureone.com' => 10888,
            'api.github.com' => 8342,
            'api.notion.com' => 728,
            'api.telegram.org' => 256,
        ]);

        $this->assertNotContains('dominant', $report['entries']['cybersecureone.com']['flags']);

        $this->allowlist->setAllowlist(['github.com']);
        $report = $this->allowlist->coverage(['api.github.com' => 8342, 'api.notion.com' => 10]);

        $this->assertContains('dominant', $report['entries']['github.com']['flags']);
    }

    public function test_coverage_without_a_sample_says_so_rather_than_reporting_zero(): void
    {
        $this->allowlist->setAllowlist(['example.com']);

        $report = $this->allowlist->coverage([]);

        $this->assertFalse($report['basis'], 'an empty sample is not evidence of anything');
        $this->assertSame(0, $report['rows']);
        $this->assertSame(0.0, $report['suppressed_fraction']);

        // Critically, the entry is NOT flagged as matching nothing: we did not
        // look, which is not the same as having looked and found nothing.
        $this->assertSame([], $report['entries']['example.com']['flags']);
    }

    /**
     * The silent half, on this host's real traffic.
     *
     * With nothing configured, the automatic recognition must excuse the
     * container names and nothing else. Bounded to the tail of the log so this
     * stays a unit test, and skipped rather than failed where the log is absent
     * or DNS logging is off, because "we could not look" is not the same finding
     * as "there was nothing there".
     */
    public function test_auto_recognition_is_not_a_blanket_on_real_traffic(): void
    {
        $counts = $this->liveDnsCounts();

        if (array_sum($counts) < 500) {
            $this->markTestSkipped('no live DNS telemetry to replay: ' . array_sum($counts) . ' rows');
        }

        $report = $this->allowlist->coverage($counts);

        $this->assertSame(0, $report['allowed_rows'], 'nothing is configured, so nothing is allowlisted');

        // Measured 2.20% (510 of 23,234) over the 47-minute corpus. The bound
        // is deliberately loose, because this asserts a property (recognition
        // is a sliver of the stream, not a blanket) rather than reproducing one
        // window's arithmetic.
        $this->assertLessThan(
            0.05,
            $report['suppressed_fraction'],
            'internal recognition excused ' . round(100 * $report['suppressed_fraction'], 2) . '% of real DNS'
        );

        // Every excused row is under a reserved suffix or dotless, and no
        // configured entry was involved in any of it.
        $excused = [];

        foreach ($report['internal'] as $suffix => $stats) {
            if ($stats['rows'] > 0) {
                $excused[] = $suffix;
            }
        }

        $this->assertSame(
            [],
            array_diff($excused, array_merge(DnsAllowlist::RESERVED_INTERNAL_SUFFIXES, ['(dotless)'])),
            'only the reserved set and the dotless rule may excuse anything by default'
        );
    }

    /**
     * The firing half, on the same real traffic: the one entry this module
     * genuinely needs must work, and must be visible in the report.
     */
    public function test_the_agents_own_control_plane_can_be_allowlisted_and_is_reported(): void
    {
        $counts = $this->liveDnsCounts();

        if (array_sum($counts) < 500) {
            $this->markTestSkipped('no live DNS telemetry to replay: ' . array_sum($counts) . ' rows');
        }

        // DnsEventNormalizer's docblock: the busiest domain on this host is the
        // product's own control plane, and a rarity rule has to be told about it
        // by domain because there is no process name to filter on. This is that
        // entry.
        $this->allowlist->setAllowlist(['cybersecureone.com']);

        $report = $this->allowlist->coverage($counts);

        $this->assertSame([], $this->allowlist->refused(), 'the one entry the module needs must be accepted');
        $this->assertGreaterThan(0, $report['entries']['cybersecureone.com']['rows']);
        $this->assertNotContains('matches_nothing', $report['entries']['cybersecureone.com']['flags']);

        // And it is reported, not hidden: measured 46.86% of the corpus, which
        // is a number an operator should have to look at, and the reason a
        // volumetric refusal ceiling would have refused the most defensible
        // entry there is.
        $this->assertGreaterThan(0.1, $report['entries']['cybersecureone.com']['fraction']);

        // The other direction, on real names from the same stream: a public
        // name that is not under the entry is still evaluated.
        $this->assertSame('evaluate', $this->allowlist->classify($this->event(self::QUERY_DYNDNS))['verdict']);
        $this->assertSame('allowed', $this->allowlist->classify($this->event(self::QUERY_CONTROL_PLANE))['verdict']);
    }

    /**
     * rrname => row count from the tail of the live log.
     *
     * Reads lines and hands them to the normaliser rather than adding a cursor:
     * there is one cursor over eve.json and DnsEventNormalizer explains why
     * there must not be a second. The tail is bounded so this stays a unit test.
     *
     * @return array<string, int>
     */
    private function liveDnsCounts(int $tailBytes = 16 * 1024 * 1024, int $cap = 25000): array
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

        $counts = [];
        $rows = 0;

        while ($rows < $cap && ($line = fgets($handle)) !== false) {
            if (!str_contains($line, '"event_type":"dns"')) {
                continue;
            }

            $event = $this->normalizer->normalizeLine($line);

            if ($event === null) {
                continue;
            }

            $rows++;
            $name = $event['dns']['rrname'];
            $counts[$name] = ($counts[$name] ?? 0) + 1;
        }

        fclose($handle);

        return $counts;
    }
}
