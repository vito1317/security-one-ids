<?php

namespace Tests\Unit;

use App\Services\Network\DnsEventNormalizer;
use App\Services\Network\DomainResolutionMap;
use Tests\TestCase;

/**
 * The domain-to-address index that gives a connection a name.
 *
 * Every DNS row in here was copied byte for byte out of this host's live
 * /var/log/suricata/eve.json, including the four answers that put one address
 * (125.228.166.197) under four different domains and the answer that returns
 * eight IPv6 addresses in a form no other sensor on this host uses. The awkward
 * rows are the point: a store keyed on invented data agrees with every
 * assumption it was built on.
 *
 * Both directions are proved, which for an index means something slightly
 * different from a rule. The positive direction is that a recorded mapping is
 * found, that the eight IPv6 addresses join, and that an address four domains
 * claim comes back with four candidates. The negative direction is that nothing
 * is ever invented: an expired mapping, an address nobody resolved, an
 * instant before the mapping was learned and a store that cannot be opened all
 * return null, each with its own counted reason, and the last test replays this
 * host's real DNS traffic and requires that every domain the store names for an
 * address is one the log actually showed for that address.
 */
class DomainResolutionMapTest extends TestCase
{
    /** A real A answer: one address, TTL 27, so it expires quickly. */
    private const ANSWER_TELEGRAM = '{"timestamp":"2026-08-28T23:05:50.825603+0800","flow_id":1835623357181964,"event_type":"dns","src_ip":"192.168.1.114","src_port":38886,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":45074,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"api.telegram.org","rrtype":"A","rcode":"NOERROR","answers":[{"rrname":"api.telegram.org","rrtype":"A","ttl":27,"rdata":"149.154.166.110"}],"grouped":{"A":["149.154.166.110"]}}}';

    /** The matching real query, which carries no address and must record nothing. */
    private const QUERY_TELEGRAM = '{"timestamp":"2026-08-28T23:05:50.820605+0800","flow_id":1835623357181964,"event_type":"dns","src_ip":"192.168.1.114","src_port":38886,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":45074,"rrname":"api.telegram.org","rrtype":"A","tx_id":0,"opcode":0}}';

    /**
     * Four real answers, four different domains, one address. That address is
     * this product's own front end and it is the busiest thing on this host:
     * 30.6% of everything the store could attribute landed on an address with
     * more than one claimant. Note the TTLs differ (200 against 60), which is
     * what makes the freshest claim orderable.
     */
    private const ANSWER_WAF = '{"timestamp":"2026-08-28T23:05:29.675067+0800","flow_id":340812526310459,"event_type":"dns","src_ip":"192.168.1.114","src_port":32941,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":22601,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"waf.cybersecureone.com","rrtype":"A","rcode":"NOERROR","answers":[{"rrname":"waf.cybersecureone.com","rrtype":"A","ttl":200,"rdata":"125.228.166.197"}],"grouped":{"A":["125.228.166.197"]}}}';
    private const ANSWER_WAF_JAPAN = '{"timestamp":"2026-08-28T23:06:51.710494+0800","flow_id":1078143313180969,"event_type":"dns","src_ip":"192.168.1.114","src_port":36926,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":375,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"waf-japan.cybersecureone.com","rrtype":"A","rcode":"NOERROR","answers":[{"rrname":"waf-japan.cybersecureone.com","rrtype":"A","ttl":60,"rdata":"125.228.166.197"}],"grouped":{"A":["125.228.166.197"]}}}';
    private const ANSWER_PAI = '{"timestamp":"2026-08-28T23:05:41.613724+0800","flow_id":1542412133594405,"event_type":"dns","src_ip":"192.168.1.114","src_port":39720,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":51631,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"pai.vito1317.com","rrtype":"A","rcode":"NOERROR","answers":[{"rrname":"pai.vito1317.com","rrtype":"A","ttl":60,"rdata":"125.228.166.197"}],"grouped":{"A":["125.228.166.197"]}}}';
    private const ANSWER_LOGIFY = '{"timestamp":"2026-08-28T23:06:54.137065+0800","flow_id":1481692432002357,"event_type":"dns","src_ip":"192.168.1.114","src_port":46491,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":56522,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"logify.intellitrustme.com","rrtype":"A","rcode":"NOERROR","answers":[{"rrname":"logify.intellitrustme.com","rrtype":"A","ttl":60,"rdata":"125.228.166.197"}],"grouped":{"A":["125.228.166.197"]}}}';

    /** A real answer with eight IPv6 addresses, all fully expanded on the wire. */
    private const ANSWER_EIGHT_IPV6 = '{"timestamp":"2026-08-28T23:10:00.511536+0800","flow_id":187317327373788,"event_type":"dns","src_ip":"192.168.1.114","src_port":37690,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":12487,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"jules.googleapis.com","rrtype":"AAAA","rcode":"NOERROR","answers":[{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4840:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4842:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4841:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4843:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4845:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4846:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4844:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4847:0400:0000:0000:0000:0000"}],"grouped":{"AAAA":["2001:4860:4840:0400:0000:0000:0000:0000","2001:4860:4842:0400:0000:0000:0000:0000","2001:4860:4841:0400:0000:0000:0000:0000","2001:4860:4843:0400:0000:0000:0000:0000","2001:4860:4845:0400:0000:0000:0000:0000","2001:4860:4846:0400:0000:0000:0000:0000","2001:4860:4844:0400:0000:0000:0000:0000","2001:4860:4847:0400:0000:0000:0000:0000"]}}}';

    /**
     * A real three-hop CNAME chain. The chain targets are names, and 5,190 of
     * the 11,182 measured answers named no address at all, so both shapes have
     * to be handled without putting a hostname into an address index.
     */
    private const ANSWER_CNAME_CHAIN = '{"timestamp":"2026-08-28T23:05:29.648187+0800","flow_id":484047709646494,"event_type":"dns","src_ip":"192.168.1.114","src_port":46226,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":49917,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"mobile.events.data.microsoft.com","rrtype":"A","rcode":"NOERROR","answers":[{"rrname":"mobile.events.data.microsoft.com","rrtype":"CNAME","ttl":8,"rdata":"mobile.events.data.trafficmanager.net"},{"rrname":"mobile.events.data.trafficmanager.net","rrtype":"CNAME","ttl":2,"rdata":"onedscolprdeus03.eastus.cloudapp.azure.com"},{"rrname":"onedscolprdeus03.eastus.cloudapp.azure.com","rrtype":"A","ttl":2,"rdata":"20.42.73.24"}],"grouped":{"CNAME":["mobile.events.data.trafficmanager.net","onedscolprdeus03.eastus.cloudapp.azure.com"],"A":["20.42.73.24"]}}}';

    /** A real NOERROR answer that names no address: an AAAA lookup of an A-only name. */
    private const ANSWER_NO_ADDRESS = '{"timestamp":"2026-08-28T23:05:29.674768+0800","flow_id":340812526310459,"event_type":"dns","src_ip":"192.168.1.114","src_port":32941,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":20800,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"waf.cybersecureone.com","rrtype":"AAAA","rcode":"NOERROR","authorities":[{"rrname":"cybersecureone.com","rrtype":"SOA","ttl":200,"soa":{"mname":"ns1.cybersecureone.com","rname":"admin.cybersecureone.com","serial":2608282303,"refresh":3600,"retry":900,"expire":604800,"minimum":300}}]}}';

    private const LIVE_LOG = '/var/log/suricata/eve.json';

    /** 2026-08-28T23:05:50+0800, the instant of the telegram answer above. */
    private const T_TELEGRAM = 1787929550;

    private string $path;
    private DomainResolutionMap $map;
    private DnsEventNormalizer $normalizer;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-dnsmap-' . uniqid() . '.sqlite';
        $this->map = new DomainResolutionMap($this->path);
        $this->normalizer = new DnsEventNormalizer();
    }

    protected function tearDown(): void
    {
        $this->map->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    /** A real log line, normalised, so the store is fed exactly what the sensor emits. */
    private function answer(string $line): array
    {
        $event = $this->normalizer->normalizeLine($line);

        $this->assertIsArray($event, 'a real log line must normalise');

        return $event;
    }

    public function test_a_recorded_mapping_is_found(): void
    {
        $event = $this->answer(self::ANSWER_TELEGRAM);

        $this->assertSame(1, $this->map->recordAnswer($event), 'one address, one pair');

        $hit = $this->map->domainFor('149.154.166.110', self::T_TELEGRAM);

        $this->assertIsArray($hit);
        $this->assertSame('api.telegram.org', $hit['domain']);
        $this->assertTrue($hit['unique']);
        $this->assertSame(1, $hit['candidate_count']);
        $this->assertSame('149.154.166.110', $hit['address']);

        // The TTL is kept as the resolver reported it, not as the retention
        // derived from it, so a later change to the grace is visible as a policy
        // change rather than as the resolver having said something different.
        $this->assertSame(27, $hit['candidates'][0]['ttl']);
        $this->assertSame(self::T_TELEGRAM, $hit['candidates'][0]['first_seen']);
        $this->assertSame(self::T_TELEGRAM, $hit['candidates'][0]['last_seen']);
        $this->assertSame(self::T_TELEGRAM + 327, $hit['candidates'][0]['expires_at'], 'TTL 27 plus the 300 s grace');
        $this->assertSame(1, $hit['candidates'][0]['observations']);

        // The other direction.
        $this->assertSame(['149.154.166.110'], $this->map->addressesFor('api.telegram.org', self::T_TELEGRAM));

        // Nothing was skipped and nothing was missed, so the counters stay
        // usable as a blindness signal.
        $this->assertSame([], $this->map->skips());
        $this->assertSame([], $this->map->misses());
    }

    /**
     * The measured trap this class exists to avoid. An address can be
     * reassigned, so a mapping that has run out has to stop answering, and it
     * has to stop the moment it expires rather than the next time prune()
     * happens to run.
     */
    public function test_an_expired_mapping_returns_null_rather_than_a_stale_guess(): void
    {
        $this->map->recordAnswer($this->answer(self::ANSWER_TELEGRAM));

        $live = self::T_TELEGRAM + 327;

        // TTL 27 plus the 300 s grace. Measured, the grace recovers 89 of the
        // 90 real connections that arrive after their answer's TTL has run out.
        $this->assertIsArray($this->map->domainFor('149.154.166.110', $live - 1), 'still inside TTL plus grace');
        $this->assertNull($this->map->domainFor('149.154.166.110', $live), 'the expiry is exclusive');
        $this->assertNull($this->map->domainFor('149.154.166.110', $live + 86400));

        // Prune has not run, so the row is still on disk. It stops answering
        // anyway, which is what makes expiry independent of housekeeping.
        $this->assertSame(1, $this->map->basis($live)['mappings']);
        $this->assertSame(0, $this->map->basis($live)['live']);

        // Two nulls for the same address, both counted as expiry rather than as
        // "never resolved", which is a different claim entirely.
        $this->assertSame(['expired' => 2], $this->map->misses());

        // And the reverse direction agrees. An empty list is not a statement
        // that the domain has no addresses, which is why basis() exists.
        $this->assertSame([], $this->map->addressesFor('api.telegram.org', $live));
    }

    /**
     * Four different nulls, and only some of them are evidence of anything.
     * Absence of history is not evidence: a store that has recorded nothing
     * must say so, because "we have never looked" and "this address was
     * resolved by nobody" are the same return value and completely different
     * facts.
     */
    public function test_the_reason_a_lookup_answered_nothing_is_told_apart(): void
    {
        // Nothing recorded at all.
        $this->assertNull($this->map->domainFor('149.154.166.110', self::T_TELEGRAM));
        $this->assertSame(['no_basis' => 1], $this->map->misses());

        $this->map->resetCounters();
        $this->map->recordAnswer($this->answer(self::ANSWER_TELEGRAM));

        // A basis exists, and this address is not in it. Only this null is a
        // fact about the address.
        $this->assertNull($this->map->domainFor('203.0.113.99', self::T_TELEGRAM));
        $this->assertSame(['unknown_address' => 1], $this->map->misses());

        // Known, and its mapping has run out.
        $this->map->resetCounters();
        $this->assertNull($this->map->domainFor('149.154.166.110', self::T_TELEGRAM + 328));
        $this->assertSame(['expired' => 1], $this->map->misses());

        // Known, but only learned after the instant asked about. Attributing a
        // connection that happened before the resolution to that resolution
        // would invert cause and effect.
        $this->map->resetCounters();
        $this->assertNull($this->map->domainFor('149.154.166.110', self::T_TELEGRAM - 60));
        $this->assertSame(['learned_after' => 1], $this->map->misses());

        // Not an address at all.
        $this->map->resetCounters();
        $this->assertNull($this->map->domainFor('mobile.events.data.trafficmanager.net'));
        $this->assertNull($this->map->domainFor(''));
        $this->assertSame(['bad_address' => 2], $this->map->misses());
    }

    /**
     * The positive direction for the ambiguity rule, on the address that
     * actually causes it here. Returning one of four would be right a quarter
     * of the time and would look exactly as confident as a correct answer.
     */
    public function test_an_address_that_several_domains_claim_names_none_of_them(): void
    {
        foreach ([self::ANSWER_WAF, self::ANSWER_PAI, self::ANSWER_WAF_JAPAN, self::ANSWER_LOGIFY] as $line) {
            $this->assertSame(1, $this->map->recordAnswer($this->answer($line)));
        }

        // 23:06:54, the instant of the last of the four.
        $at = 1787929614;
        $hit = $this->map->domainFor('125.228.166.197', $at);

        $this->assertIsArray($hit);
        $this->assertNull($hit['domain'], 'a caller reading only this field must get "unknown", not a guess');
        $this->assertFalse($hit['unique']);
        $this->assertSame(4, $hit['candidate_count']);

        $domains = array_column($hit['candidates'], 'domain');
        $this->assertSame([
            'logify.intellitrustme.com',
            'waf-japan.cybersecureone.com',
            'pai.vito1317.com',
            'waf.cybersecureone.com',
        ], $domains, 'newest claim first, so a human reads the most recent one at the top');

        // The ordering is presentation, not a verdict, and the store says so by
        // refusing to fill in `domain` above.
        $this->assertSame(4, $this->map->basis($at)['domains']);
        $this->assertSame(1, $this->map->basis($at)['addresses']);
        $this->assertSame(1, $this->map->basis($at)['ambiguous_addresses']);

        // The three 60 s claims expire first, and once only one is left the
        // store can name it. That is the whole reason expiry and ambiguity have
        // to be answered by the same query.
        $later = 1787929614 + 361;
        $survivor = $this->map->domainFor('125.228.166.197', $later);

        $this->assertIsArray($survivor);
        $this->assertSame('waf.cybersecureone.com', $survivor['domain'], 'TTL 200 outlives the three TTL 60 claims');
        $this->assertTrue($survivor['unique']);
    }

    /**
     * The retention policy, asked for rather than restated. A test that
     * recomputes the arithmetic is a test of its own copy of the policy.
     */
    public function test_the_retention_policy_is_the_measured_one(): void
    {
        // Measured on 7,044 real address observations: TTL p50 114 s, p99 300 s,
        // max 873 s. Expiring exactly on the TTL loses 4.2% of the real
        // connections that could otherwise be attributed, because the delay
        // between an answer and the connection using it reaches p90 162 s.
        $this->assertSame(327, $this->map->retentionFor(27));
        $this->assertSame(600, $this->map->retentionFor(300));

        // 1,228 of those 7,044 observations (17.4%) carried a TTL of 30 s or
        // less and two carried 0. The grace is the floor for them.
        $this->assertSame(300, $this->map->retentionFor(0));
        $this->assertSame(330, $this->map->retentionFor(30));

        // Absence is not zero and not a median borrowed from other domains: it
        // gets the grace alone, which is still longer than the measured median
        // TTL. Measured at 0 of 7,044 observations, so this is a guard, not a
        // path.
        $this->assertSame(300, $this->map->retentionFor(null));

        // The TTL is set by whoever owns the domain, so on the traffic this
        // module exists to detect it is attacker-supplied. Six hours is the cap;
        // without it one answer would pin a mapping for 68 years.
        $this->assertSame(21600, $this->map->retentionFor(2147483647));
        $this->assertSame(21600, $this->map->retentionFor(86400));

        // A negative TTL is not a shorter-than-zero cache, it is a corrupt
        // field, and it must not produce an expiry in the past.
        $this->assertSame(300, $this->map->retentionFor(-1));
    }

    /**
     * The measured surprise from the normaliser, from the store's side: 791 of
     * 791 IPv6 addresses under dns.grouped.AAAA arrive fully expanded while
     * osquery and Suricata's flow fields use the compressed form. A store keyed
     * on one spelling and queried with the other joins nothing at all, and
     * reports a host whose IPv6 connections have no domains behind them.
     */
    public function test_an_expanded_ipv6_address_and_its_compressed_form_are_one_key(): void
    {
        $event = $this->answer(self::ANSWER_EIGHT_IPV6);

        $this->assertSame(8, $this->map->recordAnswer($event));

        // 23:10:00, the instant of the answer.
        $at = 1787929800;

        $compressed = $this->map->domainFor('2001:4860:4840:400::', $at);
        $this->assertIsArray($compressed);
        $this->assertSame('jules.googleapis.com', $compressed['domain']);

        // The form the log actually carries, which must reach the same row.
        $expanded = $this->map->domainFor('2001:4860:4840:0400:0000:0000:0000:0000', $at);
        $this->assertIsArray($expanded);
        $this->assertSame('jules.googleapis.com', $expanded['domain']);
        $this->assertSame(1, $expanded['candidates'][0]['observations'], 'one row, not two spellings of one row');

        $addresses = $this->map->addressesFor('jules.googleapis.com', $at);
        $this->assertCount(8, $addresses);

        foreach ($addresses as $address) {
            $this->assertSame(
                inet_ntop(inet_pton($address)),
                $address,
                'stored in the canonical form every other sensor here uses'
            );
        }

        // An IPv4-mapped IPv6 address is the same host as its dotted quad, and
        // osquery reports the mapped form of addresses Suricata reports as
        // quads.
        $this->map->record('api.telegram.org', ['::ffff:149.154.166.110'], 27, $at);
        $mapped = $this->map->domainFor('149.154.166.110', $at);
        $this->assertIsArray($mapped);
        $this->assertSame('api.telegram.org', $mapped['domain']);
    }

    /**
     * Two shapes that must record nothing, and neither of them is an error.
     * They are counted because a store that silently writes nothing is
     * indistinguishable from a host that resolves nothing.
     */
    public function test_what_carries_no_address_records_nothing_and_says_which(): void
    {
        // A query cannot know an address: 11,236 of the 22,418 measured rows.
        $this->assertSame(0, $this->map->recordAnswer($this->answer(self::QUERY_TELEGRAM)));

        // An answer that named no address: 5,190 of 11,182 measured answers,
        // most of them AAAA lookups of names that only have A records. The
        // resolver succeeded, and there is simply nothing here to index.
        $this->assertSame(0, $this->map->recordAnswer($this->answer(self::ANSWER_NO_ADDRESS)));

        $this->assertSame(['not_an_answer' => 1, 'no_addresses' => 1], $this->map->skips());
        $this->assertSame(0, $this->map->basis()['mappings']);

        // A CNAME target sits next to the addresses in a real grouped answer
        // section, and it is a name. Storing it would make a hostname look like
        // a resolved address to everything downstream.
        $chain = $this->answer(self::ANSWER_CNAME_CHAIN);
        $this->assertSame(1, $this->map->recordAnswer($chain), 'only the A record');
        $this->assertSame(['20.42.73.24'], $this->map->addressesFor('mobile.events.data.microsoft.com', 1787929529));

        $this->map->resetCounters();
        $this->assertSame(0, $this->map->record(
            'mobile.events.data.microsoft.com',
            ['mobile.events.data.trafficmanager.net'],
            2,
            1787929529
        ));
        $this->assertSame(['bad_address' => 1], $this->map->skips());

        // A domain with nothing usable to key on, and a timestamp that would
        // make every expiry meaningless.
        $this->map->resetCounters();
        $this->assertSame(0, $this->map->record('.', ['20.42.73.24'], 60, 1787929529));
        $this->assertSame(0, $this->map->record('api.telegram.org', ['149.154.166.110'], 60, 0));
        $this->assertSame(['bad_domain' => 1, 'bad_timestamp' => 1], $this->map->skips());
    }

    /**
     * Rows arrive from a log batch in file order with several flows
     * interleaved, and 81 of the 128 measured pairs had their TTL change
     * between observations. So a re-observation must refresh the expiry from
     * the newest answer, and an older row arriving late must not shorten it.
     */
    public function test_an_out_of_order_observation_does_not_walk_the_expiry_backwards(): void
    {
        $t = 1787929529;

        $this->map->record('waf.cybersecureone.com', ['125.228.166.197'], 200, $t);
        // The same pair seen 100 s earlier with a much shorter TTL, arriving
        // late. Applied naively it would expire the mapping 240 s early.
        $this->map->record('waf.cybersecureone.com', ['125.228.166.197'], 1, $t - 100);

        $hit = $this->map->domainFor('125.228.166.197', $t + 400);
        $this->assertIsArray($hit, 'the newest answer governs the expiry');
        $this->assertSame(200, $hit['candidates'][0]['ttl']);
        $this->assertSame($t + 500, $hit['candidates'][0]['expires_at']);
        $this->assertSame($t - 100, $hit['candidates'][0]['first_seen'], 'the older observation still widens the window');
        $this->assertSame($t, $hit['candidates'][0]['last_seen']);
        $this->assertSame(2, $hit['candidates'][0]['observations']);

        // And forwards: a later answer with a shorter TTL does shorten it,
        // because that is the resolver saying to cache less.
        $this->map->record('waf.cybersecureone.com', ['125.228.166.197'], 60, $t + 10);
        $shortened = $this->map->domainFor('125.228.166.197', $t + 400);
        $this->assertNull($shortened, 'TTL 60 from t+10 expires at t+370');
        $this->assertIsArray($this->map->domainFor('125.228.166.197', $t + 360));
    }

    /**
     * Pruning reports the two things separately because they mean different
     * things: expiry is the store working, and eviction is the store being
     * overrun. At the measured 167.6 new pairs an hour, reaching the 20,000-row
     * ceiling takes about five days of pruning never running, so a non-zero
     * eviction count is a fact about the host.
     */
    public function test_prune_reports_what_it_removed(): void
    {
        $t = 1787929529;

        $this->map->recordAnswer($this->answer(self::ANSWER_TELEGRAM));
        $this->map->recordAnswer($this->answer(self::ANSWER_EIGHT_IPV6));

        // Nothing has expired yet.
        $quiet = $this->map->prune($t);
        $this->assertSame(['available' => true, 'expired' => 0, 'evicted' => 0, 'remaining' => 9, 'ceiling' => 20000], $quiet);

        // Long after everything has expired.
        $swept = $this->map->prune($t + 86400);
        $this->assertSame(9, $swept['expired']);
        $this->assertSame(0, $swept['evicted']);
        $this->assertSame(0, $swept['remaining']);

        // A prune on an empty store is not an error and reports zeroes.
        $this->assertSame(0, $this->map->prune($t + 86400)['expired']);
    }

    /**
     * The ceiling itself, with the two classes of removal happening in one
     * pass so their counts cannot be confused for each other.
     *
     * Eviction is oldest-first on last_seen, which is the right order for an
     * index whose value is naming connections happening now, and it is only
     * safe because this store never judges novelty: dropping old rows here
     * cannot make anything look new. Detecting whatever caused the burst is the
     * rule engine's job on the event stream.
     */
    public function test_the_ceiling_evicts_the_oldest_and_reports_it(): void
    {
        $t = 1787929529;

        // 20,000 pairs at t, 30 older ones that will be evicted, and 20 already
        // expired ones that will be pruned first.
        $bulk = [];
        for ($i = 0; $i < 20000; $i++) {
            $bulk[] = long2ip((int) ip2long('10.0.0.0') + $i);
        }

        $this->assertSame(20000, $this->map->record('bulk.example.test', $bulk, 300, $t));
        $this->assertSame(30, $this->map->record('older.example.test', array_slice($bulk, 0, 30), 300, $t - 100));
        $this->assertSame(20, $this->map->record('expired.example.test', array_slice($bulk, 0, 20), 300, $t - 1000));

        $this->assertSame(20050, $this->map->basis($t)['mappings']);

        $result = $this->map->prune($t);

        $this->assertSame(20, $result['expired'], 'expiry is the store working');
        $this->assertSame(30, $result['evicted'], 'eviction is the store being overrun, and it is a separate number');
        $this->assertSame(20000, $result['remaining']);

        // The oldest went and the freshest stayed.
        $this->assertSame([], $this->map->addressesFor('older.example.test', $t));
        $this->assertSame([], $this->map->addressesFor('expired.example.test', $t));

        $survivor = $this->map->domainFor('10.0.0.0', $t);
        $this->assertIsArray($survivor);
        $this->assertSame('bulk.example.test', $survivor['domain']);
        $this->assertSame(20000, $this->map->basis($t)['mappings']);
    }

    /**
     * A store that cannot be opened must not be able to say "this address was
     * never resolved here", because that reads as a finding. It says nothing,
     * and it says why.
     */
    public function test_a_broken_store_says_nothing_rather_than_no_domain(): void
    {
        // A path under a file, so the directory cannot be created.
        $broken = new DomainResolutionMap('/proc/version/nope/dns-map.sqlite');

        $this->assertFalse($broken->isAvailable());

        $this->assertSame(0, $broken->record('api.telegram.org', ['149.154.166.110'], 27, self::T_TELEGRAM));
        $this->assertSame(['store_unavailable' => 1], $broken->skips());

        $this->assertNull($broken->domainFor('149.154.166.110', self::T_TELEGRAM));
        $this->assertSame(['store_unavailable' => 1], $broken->misses());

        $this->assertSame([], $broken->addressesFor('api.telegram.org', self::T_TELEGRAM));

        // And the basis says there is none, which is the honest answer to
        // "should I read that null as evidence".
        $this->assertFalse($broken->basis()['available']);
        $this->assertFalse($broken->prune()['available']);
    }

    public function test_the_store_file_is_not_world_readable(): void
    {
        $this->map->recordAnswer($this->answer(self::ANSWER_TELEGRAM));

        // It holds which internal names this host resolves and when, which is a
        // map of the estate.
        $this->assertFileExists($this->path);
        $this->assertSame('0600', substr(sprintf('%o', fileperms($this->path)), -4));
    }

    /**
     * The other direction, on this host's own traffic: the store never names a
     * domain the log did not show for that address, every pair it accepted can
     * be found again, and nothing is skipped except the two shapes that
     * legitimately carry no address.
     *
     * Bounded to the tail of the live log so this stays a unit test, and
     * skipped rather than failed where the log is absent or DNS logging is off,
     * because "we could not look" is not the same finding as "there was nothing
     * there".
     */
    public function test_it_names_this_hosts_real_traffic_without_inventing_anything(): void
    {
        $lines = $this->liveDnsLines();

        if (count($lines) < 500) {
            $this->markTestSkipped(
                'no live DNS telemetry to replay: ' . count($lines) . ' rows in the tail of ' . self::LIVE_LOG
            );
        }

        /** @var array<string, array<string, int>> address => domain => last seen */
        $observed = [];
        $recorded = 0;
        $pairs = 0;
        $lastTs = 0;

        foreach ($lines as $line) {
            $event = $this->normalizer->normalizeLine($line);

            if ($event === null) {
                continue;
            }

            $recorded += $this->map->recordAnswer($event);
            $lastTs = max($lastTs, $event['ts']);

            if ($event['action'] !== 'dns_answer') {
                continue;
            }

            foreach ($event['dns']['addresses'] ?? [] as $address) {
                $pairs++;
                $observed[$address][$event['dns']['rrname']] = max(
                    $observed[$address][$event['dns']['rrname']] ?? 0,
                    $event['ts']
                );
            }
        }

        if ($observed === []) {
            // Counted from the normaliser's own output rather than from the
            // store, so a store that recorded nothing fails below instead of
            // skipping here. Measured, 5,190 of 11,182 real answers name no
            // address, so a tail with none at all is possible and is a reason
            // we could not look, not a finding.
            $this->markTestSkipped('no answer in the replayed tail named an address');
        }

        $this->assertSame($pairs, $recorded, 'every address a real answer named must be recorded');

        // Only the two benign reasons. A bad_address here would mean a name
        // reached the address list; a store_unavailable would mean the writes
        // were being dropped while the counts above looked healthy.
        $this->assertSame(
            [],
            array_diff(array_keys($this->map->skips()), ['not_an_answer', 'no_addresses']),
            'nothing real should be skipped for any other reason'
        );

        $unique = 0;
        $ambiguous = 0;

        foreach ($observed as $address => $domains) {
            foreach ($domains as $domain => $lastSeen) {
                // Every pair the store accepted must be findable at the instant
                // it was last seen. A write that silently went nowhere would
                // otherwise look identical to a host that resolves nothing.
                $hit = $this->map->domainFor((string) $address, $lastSeen);

                $this->assertIsArray($hit, "recorded mapping {$domain} -> {$address} must be findable");
                $this->assertContains(
                    $domain,
                    array_column($hit['candidates'], 'domain'),
                    'the domain the log showed must be among the candidates'
                );

                // Nothing invented: every candidate is a domain this log
                // actually showed resolving to this address.
                foreach (array_column($hit['candidates'], 'domain') as $candidate) {
                    $this->assertArrayHasKey(
                        $candidate,
                        $domains,
                        "{$address} was never resolved from {$candidate} in this corpus"
                    );
                }

                $hit['unique'] ? $unique++ : $ambiguous++;
            }
        }

        $this->assertGreaterThan(0, $unique, 'most real addresses belong to exactly one domain');

        // The premise of the whole module, checked rather than assumed: the
        // resolved address is nearly unique per domain. Measured over the full
        // corpus, 7 of 112 addresses (6.3%) had more than one claimant. If
        // sharing ever became the norm this join would stop discriminating, and
        // that is a fact worth failing on rather than shipping quietly.
        $addresses = count($observed);
        $shared = count(array_filter($observed, static fn (array $d): bool => count($d) > 1));

        $this->assertLessThan(
            $addresses * 0.25,
            $shared,
            "shared addresses have gone from a minority to the norm: {$shared} of {$addresses}"
        );

        // An address from TEST-NET-3, which nothing on this host resolves. The
        // negative direction on real data: a populated store still says null.
        // Asked at the last instant the log covers rather than at now(), which
        // is the same reason domainFor() takes the connection's own timestamp:
        // by the time this test runs the newest mapping may already have
        // expired, and that would make the answer "no basis" instead of
        // "unknown address" for reasons that have nothing to do with the
        // address.
        $this->assertNull($this->map->domainFor('203.0.113.99', $lastTs));
        $this->assertArrayHasKey('unknown_address', $this->map->misses());
        $this->assertArrayNotHasKey('no_basis', $this->map->misses());

        $basis = $this->map->basis($lastTs);
        $this->assertTrue($basis['available']);
        $this->assertGreaterThan(0, $basis['mappings']);
        $this->assertGreaterThan(0, $basis['live']);
        $this->assertGreaterThan(0, $basis['window_seconds'], 'the store must be able to say how little history it has');
    }

    /**
     * @return array<int, string> raw dns lines from the tail of the live log
     */
    private function liveDnsLines(int $tailBytes = 16 * 1024 * 1024, int $cap = 25000): array
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
