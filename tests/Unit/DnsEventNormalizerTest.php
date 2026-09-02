<?php

namespace Tests\Unit;

use App\Services\Network\DnsEventNormalizer;
use App\Services\Network\SocketEventNormalizer;
use Tests\TestCase;

/**
 * Turning Suricata DNS records into the shared normalised event shape.
 *
 * Every row in here was copied byte for byte out of this host's live
 * /var/log/suricata/eve.json, including the awkward ones: an answer with no
 * address in it, an NXDOMAIN whose authority record has an empty rrname, a
 * three-hop CNAME chain, a single-label Docker service name, and eight IPv6
 * addresses written in a form no other sensor on this host uses. Invented rows
 * would have agreed with every assumption this class started with, and three of
 * those assumptions were wrong.
 *
 * Both directions are proved for the parts that make a judgement: the domain
 * flags fire on a synthetic tunnelling name, and the last test replays the
 * host's real DNS traffic and requires that nothing is rejected and nothing is
 * flagged except the container names that genuinely are single-label.
 */
class DnsEventNormalizerTest extends TestCase
{
    /** A real query, and its real answer, for the same lookup on one flow. */
    private const QUERY_TELEGRAM = '{"timestamp":"2026-08-28T23:05:50.820605+0800","flow_id":1835623357181964,"event_type":"dns","src_ip":"192.168.1.114","src_port":38886,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":45074,"rrname":"api.telegram.org","rrtype":"A","tx_id":0,"opcode":0}}';
    private const ANSWER_TELEGRAM = '{"timestamp":"2026-08-28T23:05:50.825603+0800","flow_id":1835623357181964,"event_type":"dns","src_ip":"192.168.1.114","src_port":38886,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":45074,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"api.telegram.org","rrtype":"A","rcode":"NOERROR","answers":[{"rrname":"api.telegram.org","rrtype":"A","ttl":27,"rdata":"149.154.166.110"}],"grouped":{"A":["149.154.166.110"]}}}';

    /** A real AAAA query, for the timestamp and shape assertions. */
    private const QUERY_GITHUB = '{"timestamp":"2026-08-28T23:05:29.807382+0800","flow_id":371385289636133,"event_type":"dns","src_ip":"192.168.1.114","src_port":43489,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":30044,"rrname":"api.github.com","rrtype":"AAAA","tx_id":1,"opcode":0}}';

    /**
     * A real NOERROR answer that names no address at all: an AAAA lookup of a
     * name with only A records, answered with an SOA in the authority section.
     * The single most common answer shape on this host after a plain A record.
     */
    private const ANSWER_AUTHORITY_ONLY = '{"timestamp":"2026-08-28T23:05:29.674768+0800","flow_id":340812526310459,"event_type":"dns","src_ip":"192.168.1.114","src_port":32941,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":20800,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"waf.cybersecureone.com","rrtype":"AAAA","rcode":"NOERROR","authorities":[{"rrname":"cybersecureone.com","rrtype":"SOA","ttl":200,"soa":{"mname":"ns1.cybersecureone.com","rname":"admin.cybersecureone.com","serial":2608282303,"refresh":3600,"retry":900,"expire":604800,"minimum":300}}]}}';

    /** A real NXDOMAIN. Note the authority record with an empty rrname. */
    private const ANSWER_NXDOMAIN = '{"timestamp":"2026-08-28T23:05:33.655885+0800","flow_id":1644109239592472,"event_type":"dns","src_ip":"192.168.1.114","src_port":34204,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":38508,"flags":"8183","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"host.docker.internal","rrtype":"A","rcode":"NXDOMAIN","authorities":[{"rrname":"","rrtype":"SOA","ttl":86399,"soa":{"mname":"a.root-servers.net","rname":"nstld.verisign-grs.com","serial":2026082800,"refresh":1800,"retry":900,"expire":604800,"minimum":86400}}]}}';

    /** A real three-hop CNAME chain ending in one A record. */
    private const ANSWER_CNAME_CHAIN = '{"timestamp":"2026-08-28T23:05:29.648187+0800","flow_id":484047709646494,"event_type":"dns","src_ip":"192.168.1.114","src_port":46226,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":49917,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"mobile.events.data.microsoft.com","rrtype":"A","rcode":"NOERROR","answers":[{"rrname":"mobile.events.data.microsoft.com","rrtype":"CNAME","ttl":8,"rdata":"mobile.events.data.trafficmanager.net"},{"rrname":"mobile.events.data.trafficmanager.net","rrtype":"CNAME","ttl":2,"rdata":"onedscolprdeus03.eastus.cloudapp.azure.com"},{"rrname":"onedscolprdeus03.eastus.cloudapp.azure.com","rrtype":"A","ttl":2,"rdata":"20.42.73.24"}],"grouped":{"CNAME":["mobile.events.data.trafficmanager.net","onedscolprdeus03.eastus.cloudapp.azure.com"],"A":["20.42.73.24"]}}}';

    /** A real answer with eight IPv6 addresses, all in fully expanded form. */
    private const ANSWER_EIGHT_IPV6 = '{"timestamp":"2026-08-28T23:10:00.511536+0800","flow_id":187317327373788,"event_type":"dns","src_ip":"192.168.1.114","src_port":37690,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":12487,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"jules.googleapis.com","rrtype":"AAAA","rcode":"NOERROR","answers":[{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4840:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4842:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4841:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4843:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4845:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4846:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4844:0400:0000:0000:0000:0000"},{"rrname":"jules.googleapis.com","rrtype":"AAAA","ttl":300,"rdata":"2001:4860:4847:0400:0000:0000:0000:0000"}],"grouped":{"AAAA":["2001:4860:4840:0400:0000:0000:0000:0000","2001:4860:4842:0400:0000:0000:0000:0000","2001:4860:4841:0400:0000:0000:0000:0000","2001:4860:4843:0400:0000:0000:0000:0000","2001:4860:4845:0400:0000:0000:0000:0000","2001:4860:4846:0400:0000:0000:0000:0000","2001:4860:4844:0400:0000:0000:0000:0000","2001:4860:4847:0400:0000:0000:0000:0000"]}}}';

    /**
     * The only TXT answer in the corpus, and it is this product's own DNS
     * server: PowerDNS asking whether its version is still supported. The
     * module brief records TXT as absent from this host's baseline, so a rule
     * built on that would fire, on a schedule, on our own infrastructure.
     */
    private const ANSWER_TXT_POWERDNS = '{"timestamp":"2026-08-28T23:24:37.607735+0800","flow_id":1369047600752754,"event_type":"dns","src_ip":"192.168.1.114","src_port":48196,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":11420,"flags":"8180","qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"auth-4.8.5.security-status.secpoll.powerdns.com","rrtype":"TXT","rcode":"NOERROR","answers":[{"rrname":"auth-4.8.5.security-status.secpoll.powerdns.com","rrtype":"TXT","ttl":59,"rdata":"3 Unsupported release (EOL)"}],"grouped":{"TXT":["3 Unsupported release (EOL)"]}}}';

    /** A real single-label Docker service name. Not a domain, but a real query. */
    private const QUERY_SINGLE_LABEL = '{"timestamp":"2026-08-28T23:06:15.404963+0800","flow_id":2020778053971253,"event_type":"dns","src_ip":"192.168.1.114","src_port":36505,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":32507,"rrname":"nginx-proxy","rrtype":"A","tx_id":0,"opcode":0}}';

    /**
     * The real alert row for the same telegram lookup as QUERY_TELEGRAM. Same
     * flow, same on-wire id, same microsecond, and it carries the rrname one
     * level deeper under dns.query[]. Reading it would double count.
     */
    private const ALERT_WITH_NESTED_DNS = '{"timestamp":"2026-08-28T23:05:50.820605+0800","flow_id":1835623357181964,"event_type":"alert","src_ip":"192.168.1.114","src_port":38886,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","pkt_src":"wire/pcap","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":2033966,"rev":2,"signature":"ET HUNTING Telegram API Domain in DNS Lookup","category":"Misc activity","severity":3},"dns":{"version":2,"query":[{"type":"query","id":45074,"rrname":"api.telegram.org","rrtype":"A","tx_id":0,"opcode":0}]},"app_proto":"dns","direction":"to_server"}';

    /** The real flow record for that same flow, tagged app_proto dns. */
    private const FLOW_APP_PROTO_DNS = '{"timestamp":"2026-08-28T23:10:55.382348+0800","flow_id":1835623357181964,"event_type":"flow","src_ip":"192.168.1.114","src_port":38886,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","app_proto":"dns","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":62,"bytes_toclient":78,"start":"2026-08-28T23:05:50.820605+0800","end":"2026-08-28T23:05:50.825603+0800","age":0,"state":"established","reason":"timeout","alerted":true}}';

    private const LIVE_LOG = '/var/log/suricata/eve.json';

    private DnsEventNormalizer $normalizer;

    protected function setUp(): void
    {
        parent::setUp();

        $this->normalizer = new DnsEventNormalizer();
    }

    private function event(string $line): array
    {
        $event = $this->normalizer->normalizeLine($line);

        $this->assertIsArray($event, 'a real log line must normalise');

        return $event;
    }

    /** A real line with one member replaced, so the rest stays real. */
    private function mutated(string $line, callable $mutate): ?array
    {
        $row = json_decode($line, true);
        $mutate($row);

        return $this->normalizer->normalize($row);
    }

    public function test_a_real_query_carries_the_socket_event_shape(): void
    {
        $dns = $this->event(self::QUERY_GITHUB);

        // Compared against a socket event rather than a hand-written key list,
        // because the point of the shape is that one rule engine can read both.
        // A key list in a test drifts from the real shape silently.
        $sockets = new SocketEventNormalizer();
        $socket = $sockets->normalize(
            ['action' => 'added', 'unixTime' => 1787929529, 'hostIdentifier' => 'test'],
            ['syscall' => 'connect', 'pid' => 1, 'parent' => 0, 'uid' => 0, 'path' => '/usr/bin/curl',
             'remote_address' => '8.8.8.8', 'remote_port' => '53', 'local_address' => '192.168.1.114',
             'local_port' => '0', 'family' => '2', 'protocol' => '17', 'ntime' => '1'],
        );

        $this->assertIsArray($socket);

        foreach (array_keys($socket) as $key) {
            $this->assertArrayHasKey($key, $dns, "the shared shape requires the [$key] key");
        }

        foreach (array_keys($socket['network']) as $key) {
            $this->assertArrayHasKey($key, $dns['network'], "the network convention requires [$key]");
        }

        $this->assertSame('dns_query', $dns['action']);
        $this->assertSame('suricata-dns', $dns['sensor']);

        // Unavailable at source, not missing: Suricata sees packets. pid 0 here
        // means unknown and must never be read as the kernel.
        $this->assertSame(0, $dns['pid']);
        $this->assertSame(-1, $dns['uid']);
        $this->assertSame('', $dns['path']);
        $this->assertSame('', $dns['syscall']);
    }

    public function test_the_resolver_is_the_end_of_the_flow_on_port_53(): void
    {
        $dns = $this->event(self::QUERY_GITHUB);

        $this->assertSame('8.8.8.8', $dns['network']['remote_address']);
        $this->assertSame(53, $dns['network']['remote_port']);
        $this->assertSame('192.168.1.114', $dns['network']['local_address']);

        // The opposite of the socket path, where local_port is 0 on 100% of
        // rows. Here it is a real ephemeral port, and it is what ties a query
        // to its answer inside one flow.
        $this->assertSame(43489, $dns['network']['local_port']);

        $this->assertSame(17, $dns['network']['protocol'], 'UDP');
        $this->assertSame('2', $dns['network']['family'], 'AF_INET, as the osquery path spells it');
        $this->assertSame('external', $dns['network']['scope']);

        // Every real row is UDP, so TCP is checked against a mutated real row.
        // It is not a hypothetical: a large answer falls back to TCP, and a
        // tunnelling client that wants throughput reaches for it deliberately.
        $tcp = $this->mutated(self::QUERY_GITHUB, static function (array &$row): void {
            $row['proto'] = 'TCP';
        });

        $this->assertSame(6, $tcp['network']['protocol']);

        // An unmodelled protocol is null rather than guessed, so nothing
        // downstream reads a default as a fact.
        $other = $this->mutated(self::QUERY_GITHUB, static function (array &$row): void {
            $row['proto'] = 'IPv6-ICMP';
        });

        $this->assertNull($other['network']['protocol']);
    }

    /**
     * Measured 0 of 10,522 real answers arrive with the resolver as src, so
     * this branch fires on nothing today. It is tested because if a Suricata
     * release ever logs answers in packet order, the alternative is that every
     * answer files the resolver as the local end and the whole DNS baseline
     * inverts without one error being raised.
     */
    public function test_an_answer_logged_in_packet_order_still_names_the_resolver(): void
    {
        $flipped = $this->mutated(self::ANSWER_TELEGRAM, static function (array &$row): void {
            [$row['src_ip'], $row['dest_ip']] = [$row['dest_ip'], $row['src_ip']];
            [$row['src_port'], $row['dest_port']] = [$row['dest_port'], $row['src_port']];
        });

        $this->assertIsArray($flipped);
        $this->assertSame('8.8.8.8', $flipped['network']['remote_address']);
        $this->assertSame(53, $flipped['network']['remote_port']);
        $this->assertSame('192.168.1.114', $flipped['network']['local_address']);
        $this->assertSame(38886, $flipped['network']['local_port']);
    }

    public function test_a_query_and_its_answer_stay_distinct(): void
    {
        $query = $this->event(self::QUERY_TELEGRAM);
        $answer = $this->event(self::ANSWER_TELEGRAM);

        $this->assertSame('dns_query', $query['action']);
        $this->assertSame('dns_answer', $answer['action']);

        // The on-wire id is what joins the two, and it is the same value. The
        // flow is the same too. Nothing else about them should be equal.
        $this->assertSame(45074, $query['dns']['transaction_id']);
        $this->assertSame(45074, $answer['dns']['transaction_id']);
        $this->assertSame($query['dns']['flow_id'], $answer['dns']['flow_id']);

        // Suricata's own tx_id is present on queries and absent on answers,
        // measured on the whole corpus, so it cannot be the join key.
        $this->assertSame(0, $query['dns']['tx_id']);
        $this->assertNull($answer['dns']['tx_id']);

        // Intent carries no verdict: a query has no rcode and no address list
        // at all. Null, not [], so nothing can read it as "resolved to nothing".
        $this->assertNull($query['dns']['rcode']);
        $this->assertNull($query['dns']['addresses']);
        $this->assertNull($query['dns']['address_count']);
        $this->assertNull($query['dns']['ttl']);
        $this->assertNull($query['dns']['authority_only']);

        $this->assertSame('NOERROR', $answer['dns']['rcode']);
        $this->assertSame(['149.154.166.110'], $answer['dns']['addresses']);
        $this->assertSame(1, $answer['dns']['address_count']);
        $this->assertSame(27, $answer['dns']['ttl']);
        $this->assertFalse($answer['dns']['authority_only']);
    }

    /**
     * The measured trap: 4,673 of 10,522 real answers were NOERROR with no
     * address, 4,607 of them AAAA lookups of A-only names. Read as failures,
     * that is 44% of this host's successful resolution called a failed lookup.
     */
    public function test_an_answer_with_no_address_is_not_a_failed_lookup(): void
    {
        $answer = $this->event(self::ANSWER_AUTHORITY_ONLY);

        $this->assertSame('dns_answer', $answer['action']);
        $this->assertSame('NOERROR', $answer['dns']['rcode'], 'the resolver succeeded');
        $this->assertSame('AAAA', $answer['dns']['rrtype']);

        // [] means the resolver replied and named no address. A query's null
        // means nobody asked that question. The two must not collapse.
        $this->assertSame([], $answer['dns']['addresses']);
        $this->assertSame(0, $answer['dns']['address_count']);
        $this->assertSame(0, $answer['dns']['answer_count']);
        $this->assertTrue($answer['dns']['authority_only']);
        $this->assertNull($answer['dns']['ttl'], 'no answer records, so no TTL was observed');
        $this->assertSame([], $answer['dns']['record_types']);
        $this->assertSame(0, $answer['dns']['rdata_bytes']);

        $query = $this->event(self::QUERY_GITHUB);
        $this->assertNull($query['dns']['addresses'], 'a query cannot report addresses');
        $this->assertNull($query['dns']['record_types']);
        $this->assertNull($query['dns']['rdata_bytes']);
        $this->assertNotSame($query['dns']['addresses'], $answer['dns']['addresses']);
    }

    public function test_nxdomain_is_carried_as_what_the_resolver_said(): void
    {
        $answer = $this->event(self::ANSWER_NXDOMAIN);

        $this->assertSame('NXDOMAIN', $answer['dns']['rcode']);
        $this->assertSame('host.docker.internal', $answer['dns']['rrname']);
        $this->assertSame([], $answer['dns']['addresses']);
        $this->assertTrue($answer['dns']['authority_only']);

        // A real name that does not resolve is not evidence of anything on its
        // own: this one is a container hostname and it accounted for 177 of the
        // 249 NXDOMAIN answers measured on this host.
        $this->assertTrue($answer['dns']['domain_valid']);
    }

    public function test_a_cname_chain_reports_addresses_and_the_shortest_ttl(): void
    {
        $answer = $this->event(self::ANSWER_CNAME_CHAIN);

        // The CNAME targets are names, not addresses. Folding them in would
        // send a hostname into an address reputation lookup.
        $this->assertSame(['20.42.73.24'], $answer['dns']['addresses']);
        $this->assertNotContains('mobile.events.data.trafficmanager.net', $answer['dns']['addresses']);

        $this->assertSame(3, $answer['dns']['answer_count']);

        // The types are carried even where the addresses are not, because 36
        // measured answers held a CNAME and no address at all, and without the
        // type list those are indistinguishable from a resolver that said
        // nothing. Bytes are the volume that came back, all types included.
        $this->assertSame(['A', 'CNAME'], $answer['dns']['record_types']);
        $this->assertSame(90, $answer['dns']['rdata_bytes']);

        // Minimum, not first: the chain's records carry TTLs 8, 2 and 2, and it
        // is the 2 that says when this name must be resolved again. Reading the
        // first record would have reported 8 and understated the churn by 4x.
        $this->assertSame(2, $answer['dns']['ttl']);
    }

    /**
     * The one genuine surprise in the data: 791 of 791 IPv6 addresses under
     * dns.grouped.AAAA arrive fully expanded, while osquery and Suricata's own
     * flow fields use the compressed form. Carried verbatim, no IPv6 resolution
     * would ever join the connection that followed it.
     */
    public function test_expanded_ipv6_addresses_are_canonicalised_so_they_can_join(): void
    {
        $answer = $this->event(self::ANSWER_EIGHT_IPV6);

        $this->assertSame(8, $answer['dns']['address_count']);
        $this->assertContains('2001:4860:4840:400::', $answer['dns']['addresses']);
        $this->assertNotContains(
            '2001:4860:4840:0400:0000:0000:0000:0000',
            $answer['dns']['addresses'],
            'the expanded form joins nothing'
        );

        foreach ($answer['dns']['addresses'] as $address) {
            $this->assertSame(
                inet_ntop(inet_pton($address)),
                $address,
                'every address must be in the canonical form the other sensors use'
            );
        }
    }

    public function test_the_timestamp_is_the_event_time_to_the_microsecond(): void
    {
        $dns = $this->event(self::QUERY_GITHUB);

        // 2026-08-28T23:05:29.807382+0800.
        $this->assertSame(1787929529, $dns['ts']);
        $this->assertSame($dns['ts'], $dns['network']['first_seen']);
        $this->assertSame($dns['ts'], $dns['network']['last_seen']);

        $this->assertEqualsWithDelta(1787929529.807382, $dns['network']['event_time_wall'], 0.000002);

        // Unlike the osquery path there is no kernel clock in eve.json, so this
        // stays null rather than being filled with a wall clock. The aggregator
        // then falls back to whole seconds, which means DNS regularity cannot
        // be established from that field instead of being established wrongly.
        $this->assertNull($dns['network']['event_time_monotonic']);
    }

    public function test_a_timestamp_with_no_offset_is_rejected_rather_than_guessed(): void
    {
        // There is no single right answer to what an offsetless stamp means
        // here: PHP's ini default is UTC (which is what this test process
        // uses), the application sets Asia/Taipei, and the log carries +0800.
        // Reading one would give two instants eight hours apart depending on
        // who read the log.
        $this->assertNull($this->normalizer->eventTime('2026-08-28T23:05:29.807382'));

        // Z is accepted, because that is what an eve-log configured for UTC
        // writes. 15:05:29Z is the same instant as 23:05:29+0800.
        $this->assertEqualsWithDelta(
            1787929529.807382,
            (float) $this->normalizer->eventTime('2026-08-28T15:05:29.807382Z'),
            0.000002
        );

        // A rolled-over date is a wrong answer wearing the shape of a right
        // one: without the strict check, 30 February parses as 2 March.
        $this->assertNull($this->normalizer->eventTime('2026-02-30T00:00:00.000000+0800'));
        $this->assertNull($this->normalizer->eventTime('tomorrow'));
        $this->assertNull($this->normalizer->eventTime(''));
        $this->assertNull($this->normalizer->eventTime(null));
    }

    public function test_real_domains_pass_through_unchanged(): void
    {
        foreach ([self::QUERY_GITHUB, self::ANSWER_TELEGRAM, self::ANSWER_CNAME_CHAIN, self::ANSWER_NXDOMAIN] as $line) {
            $dns = $this->event($line);

            $this->assertNull($dns['dns']['rrname_raw'], 'nothing was changed, so nothing is carried');
            $this->assertSame([], $dns['dns']['domain_flags']);
            $this->assertTrue($dns['dns']['domain_valid']);
        }

        $this->assertSame('api.telegram.org', $this->event(self::ANSWER_TELEGRAM)['dns']['rrname']);
    }

    /**
     * Measured 0 of the corpus needed either fix. It is done anyway because DNS
     * is case-insensitive on the wire: 0x20 encoding is one config line away in
     * unbound and BIND, and an attacker can vary case for free. A baseline
     * keyed on the raw string would then see a new domain on nearly every
     * query, so a "never seen before" rule fires on everything and a frequency
     * baseline never converges.
     */
    public function test_case_and_the_trailing_dot_are_normalised_even_though_this_host_never_needs_it(): void
    {
        $dns = $this->mutated(self::QUERY_GITHUB, static function (array &$row): void {
            $row['dns']['rrname'] = 'API.GitHub.COM.';
        });

        $this->assertIsArray($dns);
        $this->assertSame('api.github.com', $dns['dns']['rrname']);
        $this->assertSame('API.GitHub.COM.', $dns['dns']['rrname_raw'], 'the change is visible, not inferred');
        $this->assertTrue($dns['dns']['domain_valid']);
        $this->assertSame([], $dns['dns']['domain_flags']);
    }

    public function test_a_container_service_name_is_flagged_not_dropped(): void
    {
        $dns = $this->event(self::QUERY_SINGLE_LABEL);

        $this->assertSame('nginx-proxy', $dns['dns']['rrname']);
        $this->assertSame(['single_label'], $dns['dns']['domain_flags']);
        $this->assertFalse($dns['dns']['domain_valid']);

        // 124 of 21,092 real events, plus 4 for a bare `invalid`. Rejecting
        // single-label names would delete real telemetry to enforce a rule
        // about public DNS on a host that resolves container names.
        $this->assertSame([], $this->normalizer->rejections());
    }

    /**
     * The positive direction for the flags. A tunnelling name is exactly the
     * shape a length validator throws away, which is why this class flags
     * instead: dropping it would delete the evidence for the detection the
     * module exists to make, and report a clean result while doing it.
     */
    public function test_a_tunnelling_shaped_name_is_carried_with_flags(): void
    {
        $label = str_repeat('a3f9b2c8d1e7', 6);
        $this->assertGreaterThan(63, strlen($label));

        $name = $label . '.' . str_repeat('7c2e9f14', 22) . '.exfil.example.com';
        $this->assertGreaterThan(253, strlen($name));

        $dns = $this->mutated(self::QUERY_GITHUB, static function (array &$row) use ($name): void {
            $row['dns']['rrname'] = $name;
        });

        $this->assertIsArray($dns, 'the row must survive, flagged');
        $this->assertSame($name, $dns['dns']['rrname']);
        $this->assertFalse($dns['dns']['domain_valid']);
        $this->assertContains('label_too_long', $dns['dns']['domain_flags']);
        $this->assertContains('name_too_long', $dns['dns']['domain_flags']);

        $odd = $this->normalizer->normalizeDomain('a..b-.exfil@example.com');
        $this->assertIsArray($odd);
        $this->assertContains('empty_label', $odd['flags']);
        $this->assertContains('hyphen_edge', $odd['flags']);
        $this->assertContains('non_ldh_character', $odd['flags']);

        // Legitimate underscore names are not flagged: _dmarc and _tcp service
        // records are common, and noise in front of the shapes above is what
        // makes a flag useless.
        $this->assertSame([], $this->normalizer->normalizeDomain('_dmarc.cybersecureone.com')['flags']);
    }

    /**
     * Both of these are real rows from the same flow as QUERY_TELEGRAM, and
     * both carry a dns member. The alert even carries the same rrname and the
     * same on-wire id at the same microsecond, one level deeper under
     * dns.query[]. A normaliser keyed on the presence of a dns member instead
     * of event_type would count that lookup twice, and the lookups that trip a
     * signature are exactly the ones a detector cares about.
     */
    public function test_alert_and_flow_rows_carrying_dns_are_not_ingested(): void
    {
        $this->assertNull($this->normalizer->normalizeLine(self::ALERT_WITH_NESTED_DNS));
        $this->assertNull($this->normalizer->normalizeLine(self::FLOW_APP_PROTO_DNS));

        $this->assertSame(['not_dns_event' => 2], $this->normalizer->rejections());
    }

    public function test_a_partially_written_trailing_line_is_rejected_without_throwing(): void
    {
        // What a live log's tail looks like mid-write. LogCursor already
        // withholds the partial tail, so a non-zero count here means something
        // else is truncating lines, which is worth being able to see.
        $this->assertNull($this->normalizer->normalizeLine(substr(self::ANSWER_TELEGRAM, 0, 137)));
        $this->assertNull($this->normalizer->normalizeLine(''));
        $this->assertNull($this->normalizer->normalizeLine("\n"));

        $this->assertSame(
            ['json_decode' => 1, 'empty_line' => 2],
            $this->normalizer->rejections()
        );
    }

    /**
     * A null with no reason attached is how a sensor goes blind quietly: a
     * Suricata upgrade or a schema bump turns every row into a null and the
     * batch looks like a quiet network.
     */
    public function test_every_rejection_is_counted_by_reason(): void
    {
        $cases = [
            'no_dns_object' => static function (array &$row): void {
                unset($row['dns']);
            },
            'unknown_dns_type' => static function (array &$row): void {
                // The shape eve.json uses inside alert rows.
                $row['dns'] = ['version' => 2, 'query' => [['type' => 'query', 'rrname' => 'api.github.com']]];
            },
            'no_rrname' => static function (array &$row): void {
                unset($row['dns']['rrname']);
            },
            'rrname_unprintable' => static function (array &$row): void {
                $row['dns']['rrname'] = "api.github.com\n192.168.1.1 injected";
            },
            'bad_timestamp' => static function (array &$row): void {
                $row['timestamp'] = 'not a timestamp';
            },
        ];

        foreach ($cases as $reason => $mutate) {
            $this->normalizer->resetRejections();
            $this->assertNull($this->mutated(self::QUERY_GITHUB, $mutate), $reason);
            $this->assertSame([$reason => 1], $this->normalizer->rejections());
        }

        // A bare root query has no domain to judge and nothing to baseline.
        $this->normalizer->resetRejections();
        $this->assertNull($this->mutated(self::QUERY_GITHUB, static function (array &$row): void {
            $row['dns']['rrname'] = '.';
        }));
        $this->assertSame(['no_rrname' => 1], $this->normalizer->rejections());
    }

    /**
     * A TXT answer carries no address, and reading it as "nothing came back"
     * loses the one record type that matters most for tunnelling. This row is
     * also the counter-example to the brief's baseline: TXT was recorded as
     * never seen on this host, and the two TXT rows that exist are the
     * product's own PowerDNS running its version check.
     */
    public function test_a_txt_answer_is_visible_even_though_it_has_no_address(): void
    {
        $answer = $this->event(self::ANSWER_TXT_POWERDNS);

        $this->assertSame('TXT', $answer['dns']['rrtype']);
        $this->assertSame('NOERROR', $answer['dns']['rcode']);
        $this->assertSame([], $answer['dns']['addresses'], 'a TXT record is not an address');
        $this->assertSame(['TXT'], $answer['dns']['record_types'], 'but the type is not lost');

        // 27 bytes of "3 Unsupported release (EOL)". Size, not payload: rdata
        // can be arbitrary bytes and this event goes into a spool, while the
        // size is what separates resolution from transport.
        $this->assertSame(27, $answer['dns']['rdata_bytes']);

        $this->assertSame(1, $answer['dns']['answer_count']);
        $this->assertFalse($answer['dns']['authority_only']);
        $this->assertSame(59, $answer['dns']['ttl']);

        // Seven labels and 47 characters, the longest name in the corpus. It
        // would sit near the top of any length-based tunnelling ranking, and it
        // is a version string.
        $this->assertSame('auth-4.8.5.security-status.secpoll.powerdns.com', $answer['dns']['rrname']);
        $this->assertTrue($answer['dns']['domain_valid']);
    }

    /**
     * The other direction, on this host's own traffic: nothing is rejected, and
     * nothing is flagged except the container names that genuinely have one
     * label. A detector cannot be trusted on real data until it has been shown
     * to be quiet on it.
     *
     * Bounded to the tail of the log so this stays a unit test, and skipped
     * rather than failed where the log is absent or DNS logging is off, because
     * "we could not look" is not the same finding as "there was nothing there".
     */
    public function test_it_is_silent_on_this_hosts_real_dns_traffic(): void
    {
        $rows = $this->liveDnsLines();

        if (count($rows) < 500) {
            $this->markTestSkipped(
                'no live DNS telemetry to replay: ' . count($rows) . ' rows in the tail of ' . self::LIVE_LOG
            );
        }

        $normalized = 0;
        $flags = [];
        $actions = [];

        foreach ($rows as $line) {
            $event = $this->normalizer->normalizeLine($line);

            if ($event === null) {
                continue;
            }

            $normalized++;
            $actions[$event['action']] = ($actions[$event['action']] ?? 0) + 1;

            foreach ($event['dns']['domain_flags'] as $flag) {
                $flags[$flag] = ($flags[$flag] ?? 0) + 1;
            }
        }

        $this->assertSame([], $this->normalizer->rejections(), 'real rows must not be rejected');
        $this->assertSame(count($rows), $normalized, 'every real row must normalise');

        $this->assertArrayHasKey('dns_query', $actions);
        $this->assertArrayHasKey('dns_answer', $actions, 'queries and answers must both be recognised');

        $this->assertSame(
            [],
            array_diff(array_keys($flags), ['single_label']),
            'the only shape flagged on real traffic is the single-label container name'
        );
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
