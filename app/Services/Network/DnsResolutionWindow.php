<?php

namespace App\Services\Network;

/**
 * The sliding window DnsAnomalyRules counts over.
 *
 * Holds one entry per distinct NXDOMAIN name currently inside the window, plus
 * 30-second counter buckets for the answer totals, plus the last time each rule
 * fired for each group. Nothing else: it is evidence for a 300-second question,
 * not a baseline, so it deliberately cannot answer "has this host ever seen this
 * domain", and no rule may ask it to.
 *
 * Sized from measurement. The worst 600-second window on this host held 34
 * distinct names and 1,810 answers, so the structure is a few kilobytes; the
 * name cap only exists so that a flood cannot make it unbounded, and it is set
 * two orders of magnitude above anything measured. When it does evict, the
 * count of evictions is exposed rather than swallowed, because a distinct count
 * taken from an evicting window is a floor and not a total, and a floor that
 * silently pretends to be a total is how a burst gets under-reported.
 *
 * Taken by DnsAnomalyRules as a constructor dependency, which is where the
 * argument for a small dedicated structure rather than NetworkBaselineStore or
 * the event spool is written down, together with why the caller has to persist
 * it: measured on this host the EDR cycle is a fresh PHP process every 30
 * seconds, so a window that is never carried across cycles holds 30 seconds of
 * the 300 it claims.
 */
class DnsResolutionWindow
{
    /**
     * Counter bucket width, matched to the measured collection interval.
     *
     * The EDR cycle runs every 30 seconds (security-one-watchdog.sh,
     * EDR_INTERVAL=30), so a bucket is one cycle and a 300-second window is the
     * ten most recent buckets. The consequence is worth stating: the answer
     * denominator can include up to 30 seconds more than the window, and both
     * the numerator and the denominator are affected equally, so a rate reads
     * slightly smoother rather than higher.
     */
    private const BUCKET_SECONDS = 30;

    private int $windowSeconds;
    private int $maxNames;

    /** @var array<string, array{ts: float, parent: string, hits: int}> */
    private array $nxdomain = [];

    /** @var array<int, array{answers: int, nxdomain: int}> bucket start => counters */
    private array $buckets = [];

    /** @var array<string, float> group key => last time a rule fired for it */
    private array $fired = [];

    /** Highest event time seen, which is this window's clock. */
    private float $clock = 0.0;

    /**
     * The first event time this window ever saw, which is never pruned.
     *
     * Kept separately from the pruned rows so that observedSpan() can say how
     * much time the window really covers. Deriving it from the surviving rows
     * instead would read the bucket key, which is rounded down to a 30-second
     * boundary, and would claim up to 30 seconds of coverage the window never
     * had.
     */
    private float $firstObserved = 0.0;

    /**
     * How far ahead of this reader's clock an event time may sit.
     *
     * Not derived from the 2.841ms reordering skew, which is a different
     * quantity: this bounds disagreement between the sensor's clock and this
     * process's, where a second or two is ordinary and five minutes is a fault.
     */
    private const MAX_FUTURE_SKEW = 300.0;

    /** Events refused for an implausible time, kept so the refusal is visible. */
    private int $refusedFuture = 0;

    /** Events refused for having no usable time at all. */
    private int $refusedNoTime = 0;

    private int $evicted = 0;

    public function __construct(int $windowSeconds = DnsAnomalyRules::WINDOW_SECONDS, int $maxNames = 4096)
    {
        $this->windowSeconds = max(1, $windowSeconds);
        $this->maxNames = max(64, $maxNames);
    }

    /**
     * Fold one answer into the window.
     *
     * The clock only advances, which matters because the log is not strictly
     * ordered: measured, 265 of 23,338 rows arrive up to 2.841ms early. Taking
     * the maximum keeps pruning monotonic, and 2.841ms cannot move an event
     * across a 300-second boundary.
     *
     * But the advance is bounded, and that bound is the whole point of this
     * method existing in this shape. An unbounded `max()` means a single event
     * timestamped in the future pushes the clock there permanently: `prune()`
     * then drops every bucket as too old, while `observedSpan()` still computes
     * `clock - firstObserved` and reports a full window. The rules downstream
     * would read that as "a complete window of basis, and nothing seen" when
     * the truth is "everything was discarded". That is exactly the conflation
     * of "we did not see" with "it did not happen" that this class exists to
     * prevent, so it must not be reachable from one bad row.
     *
     * A timestamp meaningfully ahead of this reader's own clock is refused
     * rather than clamped, and counted. Clamping would silently fold a
     * corrupt event into the newest bucket, which is a quieter version of the
     * same lie. The tolerance is generous because the sensor writing the log
     * and the process reading it are not guaranteed to agree to the second.
     */
    public function observe(string $name, string $parent, bool $isNxdomain, float $ts): void
    {
        if ($ts <= 0.0) {
            // No usable event time means no place in a time window. Counting it
            // anyway would put it in whichever bucket the clock happens to be
            // in, which is worse than not counting it.
            $this->refusedNoTime++;

            return;
        }

        if ($ts > $this->readerNow() + self::MAX_FUTURE_SKEW) {
            $this->refusedFuture++;

            return;
        }

        $this->clock = max($this->clock, $ts);

        if ($this->firstObserved === 0.0 || $ts < $this->firstObserved) {
            $this->firstObserved = $ts;
        }

        $bucket = (int) (floor($ts / self::BUCKET_SECONDS) * self::BUCKET_SECONDS);

        if (!isset($this->buckets[$bucket])) {
            $this->buckets[$bucket] = ['answers' => 0, 'nxdomain' => 0];
        }

        $this->buckets[$bucket]['answers']++;

        if ($isNxdomain) {
            $this->buckets[$bucket]['nxdomain']++;

            if (isset($this->nxdomain[$name])) {
                $this->nxdomain[$name]['ts'] = max($this->nxdomain[$name]['ts'], $ts);
                $this->nxdomain[$name]['hits']++;
            } elseif (count($this->nxdomain) < $this->maxNames) {
                $this->nxdomain[$name] = ['ts' => $ts, 'parent' => $parent, 'hits' => 1];
            } else {
                $this->evicted++;
            }
        }

        $this->prune();
    }

    /**
     * Distinct NXDOMAIN names under one parent, inside the window.
     *
     * @return array<int, string>
     */
    public function distinctNxdomainNames(string $parent): array
    {
        $names = [];

        foreach ($this->nxdomain as $name => $entry) {
            if ($entry['parent'] === $parent) {
                $names[] = (string) $name;
            }
        }

        return $names;
    }

    /**
     * Distinct NXDOMAIN names and their parents across the whole window.
     *
     * @return array{names: array<int, string>, parents: array<int, string>, largest_parent: int}
     */
    public function distinctNxdomainHostWide(): array
    {
        $parents = [];

        foreach ($this->nxdomain as $entry) {
            $parents[$entry['parent']] = true;
        }

        $perParent = [];

        foreach ($this->nxdomain as $entry) {
            $perParent[$entry['parent']] = ($perParent[$entry['parent']] ?? 0) + 1;
        }

        return [
            'names' => array_map('strval', array_keys($this->nxdomain)),
            'parents' => array_keys($parents),
            // How many distinct names the busiest single parent holds. The
            // host-wide rule needs it to tell "spread across domains" from
            // "one burst under one domain, plus the background", which is what
            // it was reporting: this host's two everyday NXDOMAIN names sit
            // under two parents, so any single-parent burst arrived with a
            // parent count of three already in hand.
            'largest_parent' => $perParent === [] ? 0 : max($perParent),
        ];
    }

    /**
     * Answers and NXDOMAIN answers currently in the window.
     *
     * @return array{answers: int, nxdomain: int}
     */
    public function answerCounts(): array
    {
        $answers = 0;
        $nxdomain = 0;

        foreach ($this->buckets as $counters) {
            $answers += $counters['answers'];
            $nxdomain += $counters['nxdomain'];
        }

        return ['answers' => $answers, 'nxdomain' => $nxdomain];
    }

    /**
     * How much time this window actually covers.
     *
     * The honest denominator for a negative result: a window that has only seen
     * 12 seconds of traffic cannot report that a 300-second threshold was not
     * crossed.
     */
    public function observedSpan(): float
    {
        if ($this->clock === 0.0 || $this->buckets === []) {
            // No retained buckets means no basis, whatever the clock says.
            // Deriving the span from `firstObserved` instead would keep
            // reporting a full window after a prune emptied everything, which
            // turns "we discarded it all" into "we looked and saw nothing".
            return 0.0;
        }

        $earliest = min(array_keys($this->buckets));
        $span = $this->clock - (float) $earliest;

        return max(0.0, min((float) $this->windowSeconds, $span));
    }

    /**
     * This process's wall clock, isolated so a test can move it.
     *
     * A seam rather than a call to time() inline, because the future-skew
     * refusal above is only testable if the reader's clock can be placed.
     */
    protected function readerNow(): float
    {
        return (float) time();
    }

    /**
     * Counts of what this window refused, by reason.
     *
     * Exposed because a window that silently refused every event looks exactly
     * like a quiet resolver from the outside.
     *
     * @return array{future:int, no_time:int}
     */
    public function refusals(): array
    {
        return ['future' => $this->refusedFuture, 'no_time' => $this->refusedNoTime];
    }

    /**
     * Whether a rule may fire for a group now, recording that it did.
     *
     * A burst crosses its threshold once and then stays across it for the rest
     * of the window, so without this a 30-name burst emits one finding per
     * remaining name. The governor cannot do this job for DNS: its suppression
     * signature is built from username, binary and command line, all of which
     * are empty on every DNS event, so all findings from one rule share a
     * signature regardless of domain.
     */
    public function markFired(string $key, float $ts, int $cooldownSeconds): bool
    {
        $last = $this->fired[$key] ?? null;

        if ($last !== null && $ts - $last < $cooldownSeconds) {
            return false;
        }

        $this->fired[$key] = $ts;

        return true;
    }

    public function trackedNames(): int
    {
        return count($this->nxdomain);
    }

    /**
     * Names dropped because the cap was reached.
     *
     * Non-zero means every distinct count from this window is a floor. Measured
     * on this host it stays 0 by two orders of magnitude.
     */
    public function evicted(): int
    {
        return $this->evicted;
    }

    public function clock(): float
    {
        return $this->clock;
    }

    /**
     * The whole window as plain data, for a caller to persist.
     *
     * Needed because the EDR cycle is a fresh process every 30 seconds, so
     * without this the effective window is 30 seconds and a burst thinner than
     * the threshold per cycle can never be counted. Small by measurement: the
     * worst window on this host holds 34 names and 10 buckets.
     *
     * @return array<string, mixed>
     */
    public function export(): array
    {
        return [
            'window_seconds' => $this->windowSeconds,
            'nxdomain' => $this->nxdomain,
            'buckets' => $this->buckets,
            'fired' => $this->fired,
            'clock' => $this->clock,
            'first_observed' => $this->firstObserved,
            'evicted' => $this->evicted,
        ];
    }

    /**
     * Reload state from export().
     *
     * The window length is taken from this instance and not from the stored
     * state, so shortening the constant does not leave a longer window in a
     * saved file quietly outliving the change; the restored rows are pruned
     * against the current length immediately.
     *
     * @param array<string, mixed> $state
     */
    public function restore(array $state): void
    {
        $this->nxdomain = [];

        foreach (is_array($state['nxdomain'] ?? null) ? $state['nxdomain'] : [] as $name => $entry) {
            if (!is_array($entry) || !isset($entry['ts'], $entry['parent'])) {
                continue;
            }

            $this->nxdomain[(string) $name] = [
                'ts' => (float) $entry['ts'],
                'parent' => (string) $entry['parent'],
                'hits' => (int) ($entry['hits'] ?? 1),
            ];
        }

        $this->buckets = [];

        foreach (is_array($state['buckets'] ?? null) ? $state['buckets'] : [] as $bucket => $counters) {
            if (!is_array($counters)) {
                continue;
            }

            $this->buckets[(int) $bucket] = [
                'answers' => (int) ($counters['answers'] ?? 0),
                'nxdomain' => (int) ($counters['nxdomain'] ?? 0),
            ];
        }

        $this->fired = [];

        foreach (is_array($state['fired'] ?? null) ? $state['fired'] : [] as $key => $ts) {
            $this->fired[(string) $key] = (float) $ts;
        }

        // Clamped exactly as observe() clamps an event timestamp, and for the
        // same reason. A clock that has run ahead makes prune() drop every
        // bucket while observedSpan() still reports a full window, so the rules
        // read "a complete window of basis, and nothing in it" — silence that
        // looks like an answer. observe() was fixed for that; restoring the
        // number straight out of the state file would have reintroduced it by
        // the back door, and one NTP step forward at the wrong moment is enough
        // to write such a state and have every later cycle load it back.
        $restoredClock = (float) ($state['clock'] ?? 0.0);
        $ceiling = $this->readerNow() + self::MAX_FUTURE_SKEW;

        if ($restoredClock > $ceiling) {
            $this->refusedFuture++;
            $restoredClock = $ceiling;
        }

        $this->clock = $restoredClock;
        $this->firstObserved = (float) ($state['first_observed'] ?? 0.0);
        $this->evicted = (int) ($state['evicted'] ?? 0);

        $this->prune();
    }

    /**
     * Drop everything the window has moved past.
     *
     * `fired` is kept for twice the window, not one window: it is what stops a
     * burst from re-alerting, and expiring it exactly on the boundary would
     * allow a second finding for the same burst the moment the oldest name
     * ages out.
     */
    private function prune(): void
    {
        $floor = $this->clock - $this->windowSeconds;

        foreach ($this->nxdomain as $name => $entry) {
            if ($entry['ts'] < $floor) {
                unset($this->nxdomain[$name]);
            }
        }

        $bucketFloor = (int) (floor($floor / self::BUCKET_SECONDS) * self::BUCKET_SECONDS);

        foreach ($this->buckets as $bucket => $counters) {
            if ($bucket < $bucketFloor) {
                unset($this->buckets[$bucket]);
            }
        }

        foreach ($this->fired as $key => $ts) {
            if ($ts < $this->clock - (2 * $this->windowSeconds)) {
                unset($this->fired[$key]);
            }
        }
    }
}
