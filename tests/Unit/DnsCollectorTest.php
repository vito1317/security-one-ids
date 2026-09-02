<?php

namespace Tests\Unit;

use App\Services\EdrAlertFactory;
use App\Services\EdrEventSpool;
use App\Services\Network\DnsAllowlist;
use App\Services\Network\DnsCollector;
use App\Services\Network\DnsEventNormalizer;
use App\Services\Network\DomainResolutionMap;
use App\Services\Quality\EdrGovernanceStore;
use App\Services\Quality\EdrRuleGovernor;
use DateTimeImmutable;
use DateTimeZone;
use Tests\TestCase;

/**
 * The DNS cycle end to end: a log on disk in, alerts and state out.
 *
 * The five classes this drives all have their own tests, and every one of them
 * passed for days while nothing called any of them. What is only testable here
 * is that the module executes at all, and three orderings inside it that decide
 * whether it can ever produce a finding on a real host:
 *
 *  - the counting window has to outlive the process, or a 300 second rule
 *    running in a 30 second process can only see a tenth of its own window;
 *  - the log cursor has to advance, or every cycle re-judges the same events;
 *  - only events carrying findings may be spooled, or DNS volume evicts the
 *    rest of the product's history within hours.
 */
class DnsCollectorTest extends TestCase
{
    /** A real query line from this host's eve.json, 2 September 2026. */
    private const QUERY = '{"timestamp":"2026-09-02T11:11:37.102577+0800","flow_id":440567832099415,'
        . '"event_type":"dns","src_ip":"192.168.1.114","src_port":45830,"dest_ip":"8.8.8.8","dest_port":53,'
        . '"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"query","id":36205,'
        . '"rrname":"api.github.com","rrtype":"A","tx_id":0,"opcode":0}}';

    /** A real NXDOMAIN answer from the same file. */
    private const NXDOMAIN = '{"timestamp":"2026-09-02T11:11:37.370985+0800","flow_id":438399094532785,'
        . '"event_type":"dns","src_ip":"192.168.1.114","src_port":55693,"dest_ip":"8.8.8.8","dest_port":53,'
        . '"proto":"UDP","pkt_src":"wire/pcap","dns":{"version":2,"type":"answer","id":3336,"flags":"8183",'
        . '"qr":true,"rd":true,"ra":true,"opcode":0,"rrname":"host.docker.internal","rrtype":"AAAA",'
        . '"rcode":"NXDOMAIN"}}';

    private string $dir;
    private EdrEventSpool $spool;
    private DomainResolutionMap $map;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dir = sys_get_temp_dir() . '/edr-dnscollect-' . uniqid();
        mkdir($this->dir, 0700, true);

        $this->spool = new EdrEventSpool($this->dir . '/spool.sqlite');
        $this->map = new DomainResolutionMap($this->dir . '/resmap.sqlite');
    }

    protected function tearDown(): void
    {
        $this->spool->close();
        $this->map->close();

        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir);

        parent::tearDown();
    }

    /**
     * The module runs, and says what it had to work with when it finds nothing.
     *
     * Four different facts produce an empty findings list — no new lines, lines
     * with no DNS in them, a batch the allowlist excused entirely, and a batch
     * genuinely holding nothing anomalous — and a module that has silently
     * stopped working produces the same empty list. `basis` is what separates
     * them, and it is the field that would have made this host's 2.26 days of
     * blind IDS visible on day one.
     */
    public function test_it_reports_the_basis_it_had_rather_than_only_silence(): void
    {
        $collector = $this->collector();

        $this->write([]);
        $this->assertSame('no_new_lines', $collector->collect()['stats']['basis']);

        $this->write(['{"event_type":"stats","timestamp":"2026-09-02T11:11:38.000000+0800"}']);
        $this->assertSame('no_dns_rows', $collector->collect()['stats']['basis']);

        $this->write([self::QUERY]);
        $stats = $collector->collect()['stats'];
        $this->assertSame('ok', $stats['basis']);
        $this->assertSame(1, $stats['queries']);
        $this->assertSame([], $stats['by_rule'], 'one ordinary query is not a finding');

        $missing = $this->collector($this->dir . '/no-such-log.json');
        $this->assertStringStartsWith('log_unreadable:', $missing->collect()['stats']['basis']);
    }

    /**
     * The cursor advances, so a cycle judges each event once.
     *
     * Without a commit the collector re-read the same 5,707 lines every cycle on
     * this host, which is not just wasted work: the same burst would be
     * re-observed into the window and re-judged forever.
     */
    public function test_the_cursor_advances_so_events_are_judged_once(): void
    {
        $collector = $this->collector();

        $this->write([self::QUERY, self::NXDOMAIN]);
        $this->assertSame(2, $collector->collect()['stats']['dns_rows']);
        $this->assertSame(0, $collector->collect()['stats']['dns_rows'], 'the same lines are not read twice');

        $this->append([self::QUERY]);
        $this->assertSame(1, $collector->collect()['stats']['dns_rows'], 'and a new line still arrives');
    }

    /**
     * A burst spanning cycles is one alert, not none and not one per cycle.
     *
     * This is the reason the window is written to disk at all. DNS-001 needs 12
     * distinct non-existent names inside 300 seconds; the agent runs a fresh
     * process about every 30 seconds. Held in memory the count restarts from
     * zero every cycle and the rule can only fire in the one cycle unlucky
     * enough to contain a whole burst — which on a real DGA is no cycle at all.
     *
     * Each cycle below gets its own collector, which is what a new process is.
     */
    public function test_a_burst_spanning_cycles_is_counted_across_them(): void
    {
        $found = [];
        $names = $this->generatedNames(16);

        foreach (array_chunk($names, 4) as $cycle => $chunk) {
            $lines = [];

            foreach ($chunk as $offset => $name) {
                $lines[] = $this->nxdomainFor($name, 1788000000 + ($cycle * 30) + $offset);
            }

            $this->write($lines);

            foreach ($this->collector()->collect()['stats']['by_rule'] as $rule => $count) {
                $found[$rule] = ($found[$rule] ?? 0) + $count;
            }
        }

        $this->assertSame(['DNS-001' => 1], $found, 'one burst across four cycles is one finding');

        // And the state that made it possible is on disk, readable only by the
        // account the agent runs as.
        $this->assertFileExists($this->dir . '/state.json');
        $this->assertSame('0600', substr(sprintf('%o', fileperms($this->dir . '/state.json')), -4));
    }

    /**
     * The same burst with no state between cycles reaches nothing.
     *
     * The negative half of the test above, because "it fired" proves the rule
     * works and only "it would not have fired otherwise" proves the persistence
     * is what made it work.
     */
    public function test_without_persisted_state_the_same_burst_is_never_counted(): void
    {
        $found = [];
        $names = $this->generatedNames(16);

        foreach (array_chunk($names, 4) as $cycle => $chunk) {
            $lines = [];

            foreach ($chunk as $offset => $name) {
                $lines[] = $this->nxdomainFor($name, 1788000000 + ($cycle * 30) + $offset);
            }

            $this->write($lines);

            // A fresh state path each cycle is exactly what an in-memory window
            // amounts to across a process boundary.
            $collector = $this->collector(null, $this->dir . '/state-' . $cycle . '.json');

            foreach ($collector->collect()['stats']['by_rule'] as $rule => $count) {
                $found[$rule] = ($found[$rule] ?? 0) + $count;
            }
        }

        $this->assertSame([], $found, 'four distinct names per cycle never reaches a threshold of twelve');
    }

    /**
     * Allowlisted names leave the window as well as the rules.
     *
     * Taking them out of the numerator alone leaves the denominator made of
     * traffic the module has already decided not to judge, which dilutes the
     * ratio of everything left — the hiding place the tunnelling rules
     * document for their own exemption.
     *
     * Measured on this host, this is not a corner case: all 98 NXDOMAIN answers
     * in the current log are Docker names, which the allowlist classifies
     * internal, so the window really does hold none of them.
     */
    public function test_an_allowlisted_burst_reaches_neither_the_rules_nor_the_window(): void
    {
        $lines = [];

        foreach ($this->generatedNames(20) as $offset => $name) {
            $lines[] = $this->nxdomainFor($name . '.allowed-example.com', 1788000000 + $offset);
        }

        $this->write($lines);

        $result = $this->collector()->collect(['dns_allowlist' => ['allowed-example.com']]);

        $this->assertSame([], $result['stats']['by_rule']);
        $this->assertSame(20, $result['stats']['allowlisted']);
        $this->assertSame(0, $result['stats']['judged']);
        $this->assertSame('all_allowlisted', $result['stats']['basis'], 'and it says so, rather than reading as quiet');
        $this->assertSame(0, $result['stats']['window']['tracked_names'], 'the window holds none of them either');
    }

    /**
     * Only events carrying findings are spooled.
     *
     * At this host's measured rate — 1,532 DNS rows per cycle — spooling every
     * row would add about 4.4 million rows a day against a 500,000 row ceiling
     * shared with process, file and network telemetry: roughly 2.7 hours of
     * history for the whole product. Raw socket events already did this once
     * here, which is why the socket module aggregates before it stores.
     */
    public function test_ordinary_dns_is_judged_but_not_spooled(): void
    {
        $lines = [];

        for ($i = 0; $i < 40; $i++) {
            $lines[] = $this->queryFor('api.github.com', 1788000000 + $i);
        }

        $this->write($lines);
        $stats = $this->collector()->collect()['stats'];

        $this->assertSame(40, $stats['judged'], 'every one was judged');
        $this->assertSame(0, $stats['spooled'], 'and none of them was stored');
        $this->assertSame(0, $stats['spool_pending']);
    }

    /**
     * Answers are recorded for attribution even when the allowlist excuses them.
     *
     * The resolution map names connections rather than judging them, and the
     * names an operator allowlisted are the ones a connection is most likely to
     * need attributed. Suppressing them would degrade attribution for the
     * commonest traffic on the host in exchange for nothing.
     */
    public function test_an_allowlisted_answer_is_still_recorded_for_attribution(): void
    {
        $this->write([$this->answerFor('cdn.allowed-example.com', '203.0.113.10', 1788000000)]);

        $result = $this->collector()->collect(['dns_allowlist' => ['allowed-example.com']]);

        $this->assertSame(1, $result['stats']['allowlisted']);
        $this->assertGreaterThan(0, $result['stats']['mapped'], 'the mapping is recorded regardless');

        $named = $this->map->domainFor('203.0.113.10', 1788000000 + 5);
        $this->assertSame('cdn.allowed-example.com', $named['domain'] ?? null);
    }

    /**
     * DNS is collected even when the process sensor has nothing to say.
     *
     * The two facts that make this necessary: DNS comes from Suricata, and the
     * cycle returns early twice before it reaches the rules — once when the
     * osquery results log cannot be read, once when it holds nothing new. A
     * host where osqueryd is idle, was never installed, or has just been killed
     * by an attacker takes one of those returns every cycle, and with the DNS
     * call placed after them that host would run the DNS module exactly never
     * while reporting a healthy cycle.
     *
     * The stub records that it was called, so this fails if the ordering is
     * changed back rather than merely producing a different empty array.
     */
    public function test_dns_is_collected_even_when_the_process_sensor_log_is_idle(): void
    {
        $calls = 0;

        $stub = new class($calls) extends DnsCollector {
            private int $calls = 0;

            public function __construct(int &$calls)
            {
                $this->calls = &$calls;
            }

            public function collect(array $options = []): array
            {
                $this->calls++;

                return ['alerts' => [], 'stats' => ['basis' => 'stub_ran'], 'events' => []];
            }
        };

        $this->app->instance(DnsCollector::class, $stub);

        $engine = new class($this->dir . '/no-such-osquery.log') extends \App\Services\Detection\OsqueryEngine {
            private string $logPath;

            public function __construct(string $logPath)
            {
                parent::__construct();
                $this->logPath = $logPath;
            }

            public function getResultsLogPath(): string
            {
                return $this->logPath;
            }

            public function isRunning(): bool
            {
                return false;
            }

            public function resolveBackend(): string
            {
                return 'bpf';
            }
        };

        $collector = new \App\Services\EdrEventCollector(
            $engine,
            new \App\Services\EdrRuleEngine(),
            $this->spool,
            new EdrAlertFactory(),
            new EdrRuleGovernor(new EdrGovernanceStore($this->dir . '/gov2.sqlite'))
        );

        // The results log does not exist at all: the earliest of the two returns.
        $result = $collector->collect();
        $this->assertSame('stub_ran', $result['stats']['dns']['basis'] ?? null);

        // And the log exists but holds nothing new: the second return.
        touch($this->dir . '/no-such-osquery.log');
        $result = $collector->collect();
        $this->assertSame('stub_ran', $result['stats']['dns']['basis'] ?? null);

        $this->assertSame(2, $calls, 'both early returns still run the DNS module');
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private function collector(?string $logPath = null, ?string $statePath = null): DnsCollector
    {
        return new DnsCollector(
            new DnsEventNormalizer(),
            new DnsAllowlist(),
            $this->map,
            $this->spool,
            new EdrAlertFactory(),
            new EdrRuleGovernor(new EdrGovernanceStore($this->dir . '/gov.sqlite')),
            $logPath ?? $this->dir . '/eve.json',
            $statePath ?? $this->dir . '/state.json',
            $this->dir . '/cursor.json'
        );
    }

    /** @param array<int, string> $lines */
    private function write(array $lines): void
    {
        file_put_contents($this->dir . '/eve.json', $lines === [] ? '' : implode("\n", $lines) . "\n");
    }

    /** @param array<int, string> $lines */
    private function append(array $lines): void
    {
        file_put_contents($this->dir . '/eve.json', implode("\n", $lines) . "\n", FILE_APPEND);
    }

    /**
     * Distinct generated labels under one parent, seeded so a failure repeats.
     *
     * @return array<int, string>
     */
    private function generatedNames(int $count): array
    {
        mt_srand(20260902);

        $alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
        $names = [];

        for ($i = 0; $i < $count; $i++) {
            $label = '';

            for ($c = 0; $c < 12; $c++) {
                $label .= $alphabet[mt_rand(0, strlen($alphabet) - 1)];
            }

            $names[] = $label;
        }

        return $names;
    }

    private function nxdomainFor(string $name, int $ts): string
    {
        $row = json_decode(self::NXDOMAIN, true);
        $row['timestamp'] = $this->stamp($ts);
        $row['dns']['rrname'] = str_contains($name, '.') ? $name : $name . '.dga-example.com';
        $row['dns']['rrtype'] = 'A';

        return json_encode($row);
    }

    private function queryFor(string $name, int $ts): string
    {
        $row = json_decode(self::QUERY, true);
        $row['timestamp'] = $this->stamp($ts);
        $row['dns']['rrname'] = $name;

        return json_encode($row);
    }

    private function answerFor(string $name, string $address, int $ts): string
    {
        $row = json_decode(self::NXDOMAIN, true);
        $row['timestamp'] = $this->stamp($ts);
        $row['dns']['rrname'] = $name;
        $row['dns']['rrtype'] = 'A';
        $row['dns']['rcode'] = 'NOERROR';
        $row['dns']['answers'] = [
            ['rrname' => $name, 'rrtype' => 'A', 'ttl' => 300, 'rdata' => $address],
        ];
        $row['dns']['grouped'] = ['A' => [$address]];

        return json_encode($row);
    }

    /**
     * An eve.json timestamp, in the offset the log really uses.
     *
     * Built through DateTimeImmutable rather than date(), because the process
     * timezone is not the log's: PHP's ini default here is UTC while the
     * application sets Asia/Taipei.
     */
    private function stamp(int $ts): string
    {
        return (new DateTimeImmutable('@' . $ts))
            ->setTimezone(new DateTimeZone('+08:00'))
            ->format('Y-m-d\TH:i:s') . '.000000+0800';
    }
}
