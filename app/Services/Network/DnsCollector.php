<?php

namespace App\Services\Network;

use App\Services\EdrAlertFactory;
use App\Services\EdrEventSpool;
use App\Services\LogCursor;
use App\Services\Quality\EdrRuleGovernor;
use Illuminate\Support\Facades\Log;

/**
 * Runs the DNS module inside a collect cycle.
 *
 * The five classes under this namespace that judge DNS — the normaliser, the
 * resolution window, the DGA rules, the tunnelling rules and the allowlist —
 * were each written, measured and tested on their own, and until this class
 * existed not one of them was called by anything. That is the failure mode this
 * codebase has produced seven times now, and it is worth naming precisely,
 * because it does not look like a failure from any angle except the one that
 * matters: the code is complete, the tests are green, the review passed, and it
 * never executes on the host it was written for. A module that is not wired in
 * reports no findings, and no findings is indistinguishable from a quiet host.
 *
 * THE 30 SECOND PROCESS AND THE 300 SECOND WINDOW
 *
 * The agent runs a cycle roughly every 30 seconds as a fresh PHP process, and
 * DnsAnomalyRules counts distinct names over 300 seconds. Held in memory, the
 * window would be discarded nine times out of ten before it ever reached its own
 * threshold: DNS-001 needs 12 distinct non-existent names, and a rule that can
 * only ever see a tenth of its own window cannot reach twelve except in the one
 * cycle unlucky enough to contain the whole burst. The window is therefore
 * exported to a state file at the end of every cycle and restored at the start
 * of the next, and that state carries the fired-rule cooldowns too, so a burst
 * spanning cycles is one alert rather than one per cycle.
 *
 * The state file is the reason DnsResolutionWindow::restore() clamps the clock
 * the same way observe() does: everything that arrives through this file arrives
 * from a previous run of this process, and a single NTP step forward would
 * otherwise write a clock that blinds every cycle after it.
 *
 * ONE CURSOR OVER eve.json
 *
 * Suricata writes DNS records into the same eve.json that carries its alerts.
 * Nothing else follows that file forward today — SuricataEngine::parseAlerts()
 * reads a tail window and SuricataCorrelator pages backwards from an alert
 * timestamp, neither of which is a cursor — so this class owns the only forward
 * position in it. Any future consumer of eve.json rows must take them from here
 * rather than opening a second cursor: LogCursor has had three silent bugs found
 * in it (rotation, truncate-and-rewrite, partial trailing line), and two
 * positions that can drift apart turn "why did DNS miss this" into a question
 * about which cursor was where.
 *
 * WHAT THE ALLOWLIST IS AND IS NOT ALLOWED TO SUPPRESS HERE
 *
 * A name the allowlist calls 'allowed' or 'internal' is taken out of the rules
 * AND out of the window that feeds them, numerator and denominator both. Taking
 * it out of the numerator alone would leave the hiding place DnsTunnelRules
 * documents for its own exemption: a denominator made of traffic the module has
 * already decided not to judge dilutes the ratio of everything left. The
 * NXDOMAIN rate rule inherits the same treatment for the same reason — a rate
 * over a population the module will not judge is not a rate over anything.
 *
 * The resolution map is the exception, and deliberately: an answer is recorded
 * there whatever the allowlist says. That store does not judge, it names, and
 * the names an operator allowlisted are exactly the ones a connection is most
 * likely to need attributed. Suppressing them would degrade attribution for the
 * commonest traffic on the host in exchange for nothing.
 *
 * WHAT THIS REPORTS WHEN IT FINDS NOTHING
 *
 * `stats` distinguishes "no DNS worth reporting" from "no DNS", and from "DNS
 * this module refused to judge". A cycle that read no lines, one that read lines
 * carrying no dns records, one whose whole batch was allowlisted and one that
 * genuinely saw nothing anomalous are four different facts, and all four
 * produce an empty findings list. The caller reports them alongside the
 * heartbeat so that a module which has silently stopped working is visible as
 * something other than a quiet week.
 *
 * @see DnsEventNormalizer for the event shape and the corpus these rules were
 *      measured on.
 * @see NetworkCollector for the sibling that does the same job for sockets, and
 *      for why learning happens after a batch is judged rather than during it.
 */
class DnsCollector
{
    /**
     * Bytes of eve.json read per cycle.
     *
     * Smaller than the sensor log's budget because eve.json is mostly not DNS:
     * on this host the file carries flow, stats, http and tls records in the
     * same stream, and the DNS corpus measured for these rules was 23,234 rows
     * inside a much larger file. A cycle that falls behind skips ahead rather
     * than spending the whole cycle catching up, and LogCursor reports the skip.
     */
    private const MAX_BYTES_PER_CYCLE = 4 * 1024 * 1024;

    /**
     * Ceiling on DNS events carried through one cycle.
     *
     * The tunnelling rule groups the whole batch before judging it, so this is
     * the bound on that work. Measured: this host produced 23,234 DNS rows in
     * 46 minutes, about 250 per 30 second cycle, so 20,000 is eighty times the
     * observed cycle volume and exists for the resolver storm rather than for
     * the steady state.
     */
    private const MAX_EVENTS_PER_CYCLE = 20000;

    private DnsEventNormalizer $normalizer;
    private DnsAllowlist $allowlist;
    private DomainResolutionMap $map;
    private EdrEventSpool $spool;
    private EdrAlertFactory $factory;
    private EdrRuleGovernor $governor;

    /**
     * Built here rather than injected, so that the window the rules count in is
     * the window this class persists.
     *
     * The container resolves a class-typed constructor parameter even when it
     * has a null default, so accepting these as arguments would have handed
     * DnsAnomalyRules its own private window and left this class exporting an
     * empty one every cycle — green tests, a state file that grows, and a rule
     * that never reaches its threshold.
     */
    private DnsResolutionWindow $window;
    private DnsAnomalyRules $anomalies;
    private DnsTunnelRules $tunnels;

    private ?LogCursor $cursor = null;
    private string $logPath;
    private string $statePath;
    private string $cursorPath;

    public function __construct(
        DnsEventNormalizer $normalizer,
        DnsAllowlist $allowlist,
        DomainResolutionMap $map,
        EdrEventSpool $spool,
        EdrAlertFactory $factory,
        EdrRuleGovernor $governor,
        ?string $logPath = null,
        ?string $statePath = null,
        ?string $cursorPath = null
    ) {
        $this->normalizer = $normalizer;
        $this->allowlist = $allowlist;
        $this->map = $map;
        $this->spool = $spool;
        $this->factory = $factory;
        $this->governor = $governor;

        $this->window = new DnsResolutionWindow();
        $this->anomalies = new DnsAnomalyRules($this->window);
        $this->tunnels = new DnsTunnelRules();

        $this->logPath = $logPath ?? '/var/log/suricata/eve.json';
        $this->statePath = $statePath ?? storage_path('app/edr_dns_state.json');
        $this->cursorPath = $cursorPath ?? storage_path('app/edr_dns_log_position.json');
    }

    /**
     * Read, judge and report one cycle of DNS telemetry.
     *
     * @param array $options sensor options from the Hub
     * @return array{alerts: array<int, array>, stats: array, events: array<int, array>}
     */
    public function collect(array $options = []): array
    {
        $stats = [
            'lines' => 0,
            'dns_rows' => 0,
            'queries' => 0,
            'answers' => 0,
            'rejected' => [],
            'allowlisted' => 0,
            'internal' => 0,
            'judged' => 0,
            'mapped' => 0,
            'alerts' => 0,
            'suppressed' => 0,
            'spooled' => 0,
            'spool_pending' => 0,
            'by_rule' => [],
            'window' => [],
            'basis' => 'ok',
        ];

        if (($options['dns_module_enabled'] ?? true) === false) {
            $stats['basis'] = 'disabled_by_hub';

            return ['alerts' => [], 'stats' => $stats, 'events' => []];
        }

        $this->configure($options);
        $this->restoreWindow();

        $read = $this->cursor()->read($this->logPath);
        $stats['lines'] = count($read['lines']);

        if ($read['cursor'] === null) {
            // The log is not there, or could not be stat'ed. Reported rather
            // than returned as an empty cycle: "Suricata is not writing DNS" and
            // "nothing resolved anything" are the same empty array otherwise,
            // and this host has already spent 2.26 days with the IDS blind
            // behind a green health check.
            $stats['basis'] = 'log_unreadable:' . $this->logPath;

            return ['alerts' => [], 'stats' => $stats, 'events' => []];
        }

        $events = $this->normalizeBatch($read['lines'], $stats);
        $alerts = [];

        if ($events !== []) {
            $judged = $this->classify($events, $stats);

            if ($judged === []) {
                $stats['basis'] = 'all_allowlisted';
            } else {
                $alerts = $this->evaluate($judged, $options, $stats);
            }
        } else {
            $stats['basis'] = $stats['lines'] === 0 ? 'no_new_lines' : 'no_dns_rows';
        }

        // The window is written before the cursor moves, so the ordering of the
        // two failure modes is chosen rather than accidental. Losing the window
        // costs one window of sensitivity; losing the cursor costs a re-read,
        // and a re-read is nearly free here because the window dedupes names and
        // the fired-rule cooldowns it carries stop the same burst alerting
        // twice. Fail towards re-reading.
        $this->persistWindow($stats);

        // Committed on the same condition EdrEventCollector uses: only once
        // whatever this cycle was responsible for storing is stored. Nothing to
        // store is not a failure — on this host that is the ordinary case, since
        // only events carrying findings are spooled — but a spool write that
        // failed with findings in hand holds the position so the next cycle sees
        // them again.
        if ($stats['spool_pending'] === 0 || $stats['spooled'] > 0) {
            $this->cursor()->commit($read['cursor']);
        } else {
            Log::warning('[EDR dns] Spool write failed, holding cursor to re-read next cycle', [
                'findings' => $stats['spool_pending'],
            ]);
        }

        return ['alerts' => $alerts, 'stats' => $stats, 'events' => $events];
    }

    /**
     * Apply the Hub's DNS configuration.
     *
     * Refusals are logged rather than swallowed: an entry the operator approved
     * and this class declined to store is the failure EdrExclusionSuggester
     * already produced once, where the Hub showed an exclusion as applied and
     * the only symptom was that a noisy rule kept firing.
     */
    private function configure(array $options): void
    {
        $this->allowlist->setAllowlist(is_array($options['dns_allowlist'] ?? null) ? $options['dns_allowlist'] : []);
        $this->allowlist->setInternalDomains(
            is_array($options['dns_internal_domains'] ?? null) ? $options['dns_internal_domains'] : []
        );

        if (($options['dns_internal_discovery'] ?? true) !== false) {
            $this->allowlist->discoverInternalDomains();
        }

        foreach ($this->allowlist->refused() as $refusal) {
            Log::warning('[EDR dns] Allowlist entry not applied', $refusal);
        }
    }

    /**
     * @param array<int, string> $lines
     * @return array<int, array>
     */
    private function normalizeBatch(array $lines, array &$stats): array
    {
        $events = [];

        foreach ($lines as $line) {
            if (count($events) >= self::MAX_EVENTS_PER_CYCLE) {
                $stats['basis'] = 'event_ceiling';
                break;
            }

            $event = $this->normalizer->normalizeLine($line);

            if ($event === null) {
                continue;
            }

            $action = (string) ($event['action'] ?? '');

            if ($action === 'dns_query') {
                $stats['queries']++;
            } elseif ($action === 'dns_answer') {
                $stats['answers']++;
            } else {
                continue;
            }

            $stats['dns_rows']++;
            $events[] = $event;
        }

        $stats['rejected'] = $this->normalizer->rejections();

        return $events;
    }

    /**
     * Record every answer, then keep only what the module is entitled to judge.
     *
     * Order matters and is the point: the resolution map is fed from the whole
     * batch, including allowlisted names, because it names connections rather
     * than judging them. Everything after it sees only the names no entry
     * excused.
     *
     * @param array<int, array> $events
     * @return array<int, array>
     */
    private function classify(array $events, array &$stats): array
    {
        $judged = [];

        foreach ($events as $event) {
            if ((string) ($event['action'] ?? '') === 'dns_answer') {
                $stats['mapped'] += $this->map->recordAnswer($event);
            }

            $verdict = $this->allowlist->classify($event);

            if ($verdict['verdict'] === 'allowed') {
                $stats['allowlisted']++;
                continue;
            }

            if ($verdict['verdict'] === 'internal') {
                $stats['internal']++;
                continue;
            }

            $judged[] = $event;
        }

        $stats['judged'] = count($judged);

        return $judged;
    }

    /**
     * @param array<int, array> $events
     * @return array<int, array> alerts for the dry-run view
     */
    private function evaluate(array $events, array $options, array &$stats): array
    {
        $perEvent = [];

        foreach ($events as $index => $event) {
            $findings = $this->anomalies->evaluate($event);

            if ($findings !== []) {
                $perEvent[$index] = $findings;
            }
        }

        // The tunnelling rule needs the whole batch, because its primary signal
        // is a ratio over a parent domain rather than anything visible in one
        // query. Its per-event rules run inside the same call.
        $batch = $this->tunnels->evaluateBatch($events);

        foreach ($batch['findings'] as $hit) {
            $index = $this->indexOf($events, $hit['event']);
            $perEvent[$index] = array_merge($perEvent[$index] ?? [], $hit['findings']);
        }

        $alerts = [];
        $spoolEvents = [];
        $spoolFindings = [];
        $spoolDeliverable = [];

        foreach ($perEvent as $index => $findings) {
            $event = $events[$index];
            $allowed = [];

            foreach ($findings as $finding) {
                $decision = $this->governor->assess($finding, $event, $options);
                $this->governor->record($decision, $finding, $event, $options);

                // Read without a `??` default, the way NetworkCollector reads
                // it: the first version of that line read a key the governor
                // does not return, every finding came back suppressed, and the
                // cycle reported success.
                if ($decision['emit'] === true) {
                    $finding['stage'] = $decision['stage'];
                    $finding['allow_response'] = $decision['allow_response'];
                    $allowed[] = $finding;
                    $rule = (string) ($finding['rule'] ?? '?');
                    $stats['by_rule'][$rule] = ($stats['by_rule'][$rule] ?? 0) + 1;
                } else {
                    $stats['suppressed']++;
                }
            }

            // Only events carrying a finding are spooled, and this is the one
            // decision in this class with a number behind it big enough to
            // matter. Spooling every DNS row would add about 4.4 million rows a
            // day at this host's measured rate of 1,532 rows per cycle, against
            // a 500,000 row ceiling shared with process, file and network
            // telemetry — roughly 2.7 hours of history for the whole product.
            // That is precisely what raw socket events already did once here,
            // and why NetworkCollector aggregates before it stores.
            //
            // Nothing is lost that the module needs: the resolution history
            // lives in DomainResolutionMap's own store with its own retention,
            // and a DNS row with no finding answers no question the spool is
            // asked. Suppressed findings ARE spooled, because rule tuning and
            // retro-hunt both need to see what was held back.
            $spoolIndex = count($spoolEvents);
            $spoolEvents[] = $event;
            $spoolFindings[$spoolIndex] = $findings;
            $spoolDeliverable[$spoolIndex] = $allowed !== [];

            if ($allowed !== []) {
                $alerts[] = $this->factory->fromEvent($event, $allowed);
                $stats['alerts']++;
            }
        }

        $stats['spool_pending'] = count($spoolEvents);
        $stats['spooled'] = $spoolEvents === []
            ? 0
            : $this->spool->store($spoolEvents, $spoolFindings, $spoolDeliverable);
        $stats['tunnel'] = $batch['stats'] ?? [];

        return $alerts;
    }

    /**
     * Where a rule's representative event sits in the batch.
     *
     * The group rule hands back one of the events it was given, so identity is
     * the honest test. A value comparison would collapse two queries for the
     * same name at the same instant into one index and attach a group finding to
     * whichever came first.
     *
     * @param array<int, array> $events
     */
    private function indexOf(array $events, array $needle): int
    {
        foreach ($events as $index => $event) {
            if ($event === $needle) {
                return $index;
            }
        }

        return array_key_first($events) ?? 0;
    }

    private function cursor(): LogCursor
    {
        return $this->cursor ??= new LogCursor($this->cursorPath, self::MAX_BYTES_PER_CYCLE);
    }

    /**
     * Load the counting window left by the previous cycle.
     *
     * A missing or unreadable state file starts an empty window rather than
     * failing the cycle: the cost is one window of reduced sensitivity, and the
     * alternative is a DNS module that stops entirely the first time a disk
     * fills.
     */
    private function restoreWindow(): void
    {
        $raw = @file_get_contents($this->statePath);

        if ($raw === false || $raw === '') {
            return;
        }

        $state = json_decode($raw, true);

        if (is_array($state)) {
            $this->window->restore($state);
        }
    }

    private function persistWindow(array &$stats): void
    {
        $stats['window'] = [
            'tracked_names' => $this->window->trackedNames(),
            'evicted' => $this->window->evicted(),
            'observed_span' => round($this->window->observedSpan(), 1),
            'refusals' => $this->window->refusals(),
            'exclusions' => $this->anomalies->exclusions(),
        ];

        $encoded = json_encode($this->window->export());

        if ($encoded === false) {
            Log::warning('[EDR dns] Window state could not be encoded; next cycle starts empty');

            return;
        }

        $written = @file_put_contents($this->statePath, $encoded, LOCK_EX);

        if ($written === false) {
            Log::warning('[EDR dns] Window state not written to ' . $this->statePath
                . '; every cycle will start empty and the 300s rules cannot reach their thresholds');

            return;
        }

        @chmod($this->statePath, 0600);
    }

    /** The window these rules count in, for tests and for a coverage report. */
    public function window(): DnsResolutionWindow
    {
        return $this->window;
    }

    public function allowlist(): DnsAllowlist
    {
        return $this->allowlist;
    }
}
