<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Process\Process;

/**
 * SAST + AI program-code vulnerability scanner, run locally on an IDS agent
 * and packaged into the ISO 27001 compliance report envelope as a `code_scan`
 * block (consumed by the Hub's CodeScanComplianceService).
 *
 * Three scan modes (selected by waf_config.json → `addons.code_scan_tool`):
 *   - semgrep : shell out to the `semgrep` binary when available
 *   - ai      : feed each source file to the LLM endpoint configured by the Hub
 *   - hybrid  : both, merged and de-duplicated
 *   - builtin : language-aware regex patterns (fallback when semgrep missing
 *               and AI endpoint unreachable)
 *
 * Path / language discovery is auto when those knobs are empty — the Hub
 * surfaces hint tables (webroots, project markers, extension map, exclusion
 * list) via the heartbeat so this service and the Hub agree on the contract.
 */
class CodeScanService
{
    private const DEFAULT_PATH_HINTS = [
        '/var/www/html', '/var/www', '/srv/www', '/srv/http',
        '/opt/app', '/opt',
    ];

    private const DEFAULT_MARKERS = [
        'php' => ['composer.json', 'artisan'],
        'js' => ['package.json'],
        'ts' => ['tsconfig.json', 'package.json'],
        'python' => ['pyproject.toml', 'requirements.txt', 'setup.py', 'Pipfile'],
        'go' => ['go.mod'],
        'rust' => ['Cargo.toml'],
        'java' => ['pom.xml', 'build.gradle', 'build.gradle.kts'],
        'ruby' => ['Gemfile'],
    ];

    private const DEFAULT_EXTENSIONS = [
        'php' => ['php', 'phtml'],
        'js' => ['js', 'mjs', 'cjs', 'jsx'],
        'ts' => ['ts', 'tsx'],
        'vue' => ['vue'],
        'python' => ['py'],
        'go' => ['go'],
        'rust' => ['rs'],
        'java' => ['java'],
        'ruby' => ['rb'],
        'csharp' => ['cs'],
        'c' => ['c', 'h'],
        'cpp' => ['cpp', 'hpp', 'cc', 'cxx'],
    ];

    private const DEFAULT_EXCLUDE = [
        'node_modules', 'vendor', '.git', 'storage', 'bootstrap/cache',
        'dist', 'build', '__pycache__', '.venv', 'target', 'bin', 'obj',
    ];

    /**
     * Built-in regex-based SAST patterns. Narrow but high-signal — meant as
     * a graceful-degrade path when the real SAST / AI pipeline is not
     * available. Each rule emits CWE + OWASP mapping used by the Hub UI.
     *
     * @var array<string, array<int, array<string, string>>>
     */
    private const BUILTIN_PATTERNS = [
        'php' => [
            ['id' => 'php.sqli.concat', 'severity' => 'high', 'cwe' => 'CWE-89', 'owasp' => 'A03:2021',
                'message' => '疑似 SQL 拼接注入：請改用參數化綁定 (PDO/Eloquent binding)。',
                'pattern' => '/(?:mysqli_query|mysql_query|DB::(?:select|raw))\s*\(\s*["\'][^"\']*\$/i'],
            ['id' => 'php.rce.eval', 'severity' => 'critical', 'cwe' => 'CWE-94', 'owasp' => 'A03:2021',
                'message' => '直接 eval() 變數，存在遠端程式碼執行風險。',
                'pattern' => '/\beval\s*\(\s*\$/i'],
            ['id' => 'php.rce.shell', 'severity' => 'high', 'cwe' => 'CWE-78', 'owasp' => 'A03:2021',
                'message' => '使用 system/exec/shell_exec/passthru 帶入變數，可能造成命令注入。',
                'pattern' => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*[^)]*\$[A-Za-z_]/i'],
            ['id' => 'php.xss.echo', 'severity' => 'medium', 'cwe' => 'CWE-79', 'owasp' => 'A03:2021',
                'message' => 'echo 直接輸出 $_GET/$_POST/$_REQUEST，未做 HTML escape。',
                'pattern' => '/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\b/i'],
            ['id' => 'php.file.include', 'severity' => 'high', 'cwe' => 'CWE-98', 'owasp' => 'A01:2021',
                'message' => 'include/require 使用使用者輸入，存在檔案包含弱點。',
                'pattern' => '/\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)\b/i'],
            ['id' => 'php.secret.hardcoded', 'severity' => 'medium', 'cwe' => 'CWE-798', 'owasp' => 'A07:2021',
                'message' => '硬編碼密碼/金鑰字串。',
                'pattern' => '/(?:password|passwd|api_?key|secret|token)\s*=\s*["\'][A-Za-z0-9_\-\/+]{12,}["\']/i'],
            ['id' => 'php.deserialize.unsafe', 'severity' => 'high', 'cwe' => 'CWE-502', 'owasp' => 'A08:2021',
                'message' => 'unserialize() 使用者輸入，存在反序列化弱點。',
                'pattern' => '/\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i'],
        ],
        'js' => [
            ['id' => 'js.xss.innerhtml', 'severity' => 'high', 'cwe' => 'CWE-79', 'owasp' => 'A03:2021',
                'message' => '將未消毒內容寫入 innerHTML，存在 XSS 風險。',
                'pattern' => '/\.innerHTML\s*=\s*(?!["\'`])[^;]*(?:location|params|query|input|req\.|request)/i'],
            ['id' => 'js.rce.eval', 'severity' => 'critical', 'cwe' => 'CWE-94', 'owasp' => 'A03:2021',
                'message' => '使用 eval() — 避免於前端或 Node 中使用動態 eval。',
                'pattern' => '/\beval\s*\(/'],
            ['id' => 'js.rce.newfunction', 'severity' => 'high', 'cwe' => 'CWE-94', 'owasp' => 'A03:2021',
                'message' => 'new Function() 動態建立函式等同 eval。',
                'pattern' => '/\bnew\s+Function\s*\(/'],
            ['id' => 'js.secret.hardcoded', 'severity' => 'medium', 'cwe' => 'CWE-798', 'owasp' => 'A07:2021',
                'message' => '硬編碼密碼/金鑰字串。',
                'pattern' => '/(?:password|api_?key|secret|token)\s*[:=]\s*["\'][A-Za-z0-9_\-\/+]{16,}["\']/i'],
        ],
        'python' => [
            ['id' => 'py.rce.eval', 'severity' => 'critical', 'cwe' => 'CWE-94', 'owasp' => 'A03:2021',
                'message' => 'eval() / exec() — 避免對不信任輸入動態執行。',
                'pattern' => '/\b(?:eval|exec)\s*\(/'],
            ['id' => 'py.rce.shell', 'severity' => 'high', 'cwe' => 'CWE-78', 'owasp' => 'A03:2021',
                'message' => 'os.system / subprocess.*(shell=True) 可能造成命令注入。',
                'pattern' => '/(?:os\.system\s*\(|subprocess\.[A-Za-z_]+\s*\([^)]*shell\s*=\s*True)/'],
            ['id' => 'py.deserialize.pickle', 'severity' => 'high', 'cwe' => 'CWE-502', 'owasp' => 'A08:2021',
                'message' => 'pickle.loads 使用者輸入，存在反序列化弱點。',
                'pattern' => '/\bpickle\.loads?\s*\(/'],
            ['id' => 'py.sql.concat', 'severity' => 'high', 'cwe' => 'CWE-89', 'owasp' => 'A03:2021',
                'message' => '疑似 SQL 字串拼接。',
                'pattern' => '/(?:cursor|conn)\.execute\s*\(\s*["\'][^"\']*%s[^"\']*["\']\s*%/'],
        ],
        'go' => [
            ['id' => 'go.rce.exec', 'severity' => 'high', 'cwe' => 'CWE-78', 'owasp' => 'A03:2021',
                'message' => 'exec.Command 帶入使用者輸入，可能命令注入。',
                'pattern' => '/exec\.Command\s*\([^)]*r\.(?:Form|URL|Body)/i'],
            ['id' => 'go.sql.concat', 'severity' => 'high', 'cwe' => 'CWE-89', 'owasp' => 'A03:2021',
                'message' => 'db.Query 使用 fmt.Sprintf 字串拼接 SQL。',
                'pattern' => '/db\.(?:Query|Exec)\s*\(\s*fmt\.Sprintf/i'],
        ],
    ];

    public function __construct(private readonly WafSyncService $waf)
    {
    }

    /**
     * Entry point. Reads waf_config.json, decides tool + scope, runs scan,
     * returns the payload block to embed under `code_scan` in the compliance
     * report.
     *
     * @return array<string, mixed>
     */
    public function run(): array
    {
        $cfg = $this->waf->getWafConfig();
        $addons = $cfg['addons'] ?? [];
        $enabled = (bool) ($addons['code_scan_enabled'] ?? false);

        if (! $enabled) {
            return ['enabled' => false];
        }

        $tool = (string) ($addons['code_scan_tool'] ?? 'semgrep');
        $configuredPaths = array_values(array_filter((array) ($addons['code_scan_paths'] ?? [])));
        $configuredLangs = array_values(array_filter((array) ($addons['code_scan_languages'] ?? [])));

        $hints = (array) ($addons['code_scan_auto_path_hints'] ?? self::DEFAULT_PATH_HINTS);
        $markers = (array) ($addons['code_scan_auto_markers'] ?? self::DEFAULT_MARKERS);
        $extensions = (array) ($addons['code_scan_auto_extensions'] ?? self::DEFAULT_EXTENSIONS);
        $excludes = (array) ($addons['code_scan_auto_exclude'] ?? self::DEFAULT_EXCLUDE);

        $start = microtime(true);

        $paths = empty($configuredPaths) ? $this->discoverPaths($hints, $markers) : $configuredPaths;
        $files = $this->collectFiles($paths, $extensions, $excludes, $configuredLangs);

        Log::info('Code scan starting', [
            'tool' => $tool,
            'auto_paths' => empty($configuredPaths),
            'auto_languages' => empty($configuredLangs),
            'paths' => $paths,
            'file_count' => count($files),
        ]);

        // Stage 1 — raw findings from each requested engine.
        $ruleFindings = match ($tool) {
            'ai', 'builtin' => $tool === 'builtin'
                ? $this->runBuiltin($files, $extensions)
                : [],
            'hybrid' => $this->runSemgrep($paths) ?? $this->runBuiltin($files, $extensions),
            default => $this->runSemgrep($paths) ?? $this->runBuiltin($files, $extensions),
        };
        $aiFindings = in_array($tool, ['ai', 'hybrid'], true)
            ? $this->runAiScan($files, $cfg)
            : [];

        // Skip AI stages if the LLM endpoint isn't reachable. Without this
        // probe, every triage / verify request would waste its full 90s
        // timeout on a dead endpoint.
        $aiReachable = $this->isAiReachable($cfg);

        // Stage 2 — AI triage over the rule-based hits (true-pos / false-pos).
        // Cuts the noise from built-in regex patterns (e.g. legitimate
        // proc_open / shell_exec calls in trusted cron code).
        if ($aiReachable && ! empty($ruleFindings)) {
            $ruleFindings = $this->triageFindings($ruleFindings, $cfg);
        }

        // Stage 3 — self-verification over the AI's own findings, which
        // catches line-number hallucinations and invented CWE ids.
        if ($aiReachable && ! empty($aiFindings)) {
            $aiFindings = $this->verifyAiFindings($aiFindings, $cfg);
        }

        $findings = $this->mergeFindings($ruleFindings, $aiFindings);

        // Optional suppression: when the triage flagged something as a likely
        // false-positive with high confidence, drop it from the visible
        // summary but keep the entry so operators can review.
        $visible = array_values(array_filter(
            $findings,
            fn ($f) => ($f['triage_verdict'] ?? null) !== 'likely_false_positive'
                || (float) ($f['triage_confidence'] ?? 0) < 0.8
        ));

        $summary = $this->summarize($visible);
        $duration = round(microtime(true) - $start, 2);

        return [
            'enabled' => true,
            'tool' => $tool,
            'scanned_paths' => $paths,
            'scanned_files' => count($files),
            'duration_seconds' => $duration,
            'summary' => $summary,
            'findings' => $findings,
            'stats' => [
                'rule_raw' => count($ruleFindings),
                'ai_raw' => count($aiFindings),
                'suppressed_fps' => count($findings) - count($visible),
            ],
        ];
    }

    /* ------------------------------------------------------------------ */
    /* Discovery                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Walk the hint roots looking for project-marker files. Each hit's parent
     * directory is added as a scan root; hints without any markers are also
     * added as-is if the root itself exists (covers bare webroots without
     * composer/package files).
     *
     * @param  array<int, string>  $hints
     * @param  array<string, array<int, string>>  $markers
     * @return array<int, string>
     */
    private function discoverPaths(array $hints, array $markers): array
    {
        $markerFlat = [];
        foreach ($markers as $list) {
            foreach ($list as $name) {
                $markerFlat[] = $name;
            }
        }
        $markerFlat = array_values(array_unique($markerFlat));

        $found = [];
        foreach ($hints as $hint) {
            foreach ($this->expandGlob($hint) as $root) {
                if (! is_dir($root) || ! is_readable($root)) {
                    continue;
                }

                $detected = $this->scanForMarkers($root, $markerFlat, 4);
                if (! empty($detected)) {
                    foreach ($detected as $d) {
                        $found[$d] = true;
                    }
                } else {
                    // Webroot with no obvious project marker — keep the root
                    // itself so simple PHP/JS sites still get scanned.
                    if ($this->hasCodeFiles($root)) {
                        $found[$root] = true;
                    }
                }
            }
        }

        return array_keys($found);
    }

    /**
     * Expand a single glob-style hint (e.g. /home/*\/public_html) via PHP glob.
     *
     * @return array<int, string>
     */
    private function expandGlob(string $hint): array
    {
        if (strpos($hint, '*') === false && strpos($hint, '?') === false) {
            return [$hint];
        }

        $expanded = glob($hint, GLOB_ONLYDIR) ?: [];

        return array_values($expanded);
    }

    /**
     * Walk down up to `$maxDepth` levels under `$root` looking for any of the
     * project-marker file names. Returns the directories that contain them.
     *
     * @param  array<int, string>  $markers
     * @return array<int, string>
     */
    private function scanForMarkers(string $root, array $markers, int $maxDepth): array
    {
        $matches = [];
        $queue = [[$root, 0]];
        $seen = 0;

        while ($queue && $seen < 5000) {
            [$dir, $depth] = array_shift($queue);
            $seen++;

            foreach ($markers as $name) {
                // Handle glob-style markers (e.g. *.csproj) cheaply.
                if (strpos($name, '*') !== false) {
                    if (! empty(glob($dir . DIRECTORY_SEPARATOR . $name))) {
                        $matches[$dir] = true;
                        break;
                    }
                } elseif (is_file($dir . DIRECTORY_SEPARATOR . $name)) {
                    $matches[$dir] = true;
                    break;
                }
            }

            if ($depth >= $maxDepth) {
                continue;
            }

            $entries = @scandir($dir) ?: [];
            foreach ($entries as $e) {
                if ($e === '.' || $e === '..') {
                    continue;
                }
                if (in_array($e, self::DEFAULT_EXCLUDE, true)) {
                    continue;
                }
                $sub = $dir . DIRECTORY_SEPARATOR . $e;
                if (is_dir($sub) && ! is_link($sub)) {
                    $queue[] = [$sub, $depth + 1];
                }
            }
        }

        return array_keys($matches);
    }

    /**
     * Cheap "does this directory have any code?" probe — checks the top two
     * levels for a file with a known source extension.
     */
    private function hasCodeFiles(string $root): bool
    {
        $allExt = [];
        foreach (self::DEFAULT_EXTENSIONS as $exts) {
            foreach ($exts as $e) {
                $allExt[] = ltrim(strtolower((string) $e), '.');
            }
        }
        $allExt = array_values(array_unique(array_filter($allExt)));

        foreach ([$root, ...array_slice($this->childDirs($root), 0, 20)] as $dir) {
            $entries = @scandir($dir) ?: [];
            foreach ($entries as $e) {
                if ($e === '.' || $e === '..') {
                    continue;
                }
                $ext = pathinfo($e, PATHINFO_EXTENSION);
                if (in_array(strtolower($ext), $allExt, true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return array<int, string>
     */
    private function childDirs(string $root): array
    {
        $out = [];
        foreach (@scandir($root) ?: [] as $e) {
            if ($e === '.' || $e === '..' || in_array($e, self::DEFAULT_EXCLUDE, true)) {
                continue;
            }
            $sub = $root . DIRECTORY_SEPARATOR . $e;
            if (is_dir($sub) && ! is_link($sub)) {
                $out[] = $sub;
            }
        }

        return $out;
    }

    /**
     * Collect concrete file paths under the roots, optionally filtered to
     * specific languages. Bounded to 2000 files to keep scans tractable.
     *
     * @param  array<int, string>  $roots
     * @param  array<string, array<int, string>>  $extMap
     * @param  array<int, string>  $excludes
     * @param  array<int, string>  $langs
     * @return array<int, string>
     */
    private function collectFiles(array $roots, array $extMap, array $excludes, array $langs): array
    {
        if (empty($roots)) {
            return [];
        }

        $allowedExt = [];
        foreach ($extMap as $lang => $exts) {
            if (! empty($langs) && ! in_array($lang, $langs, true)) {
                continue;
            }
            foreach ($exts as $e) {
                // Normalise: the Hub has historically sent either ".php" or
                // "php". Finder::getExtension() returns the dotless form, so
                // strip any leading dot here to keep the lookup consistent.
                $key = ltrim(strtolower((string) $e), '.');
                if ($key !== '') {
                    $allowedExt[$key] = true;
                }
            }
        }

        $files = [];
        $limit = 2000;

        foreach ($roots as $root) {
            if (! is_dir($root)) {
                continue;
            }

            try {
                $finder = Finder::create()
                    ->files()
                    ->in($root)
                    ->ignoreDotFiles(true)
                    ->ignoreVCS(true)
                    ->followLinks(false)
                    ->size('<= 512K');
                foreach ($excludes as $ex) {
                    $finder->exclude($ex);
                }
            } catch (\Throwable $e) {
                Log::debug('Finder failed for ' . $root . ': ' . $e->getMessage());
                continue;
            }

            foreach ($finder as $f) {
                if (count($files) >= $limit) {
                    break 2;
                }
                $ext = strtolower($f->getExtension());
                if (! isset($allowedExt[$ext])) {
                    continue;
                }
                $files[] = $f->getRealPath();
            }
        }

        return $files;
    }

    /* ------------------------------------------------------------------ */
    /* Scan backends                                                       */
    /* ------------------------------------------------------------------ */

    /**
     * Run semgrep. Returns null if the binary is absent or the run fails, so
     * the caller can fall back to the built-in scanner.
     *
     * @param  array<int, string>  $paths
     * @return array<int, array<string, mixed>>|null
     */
    private function runSemgrep(array $paths): ?array
    {
        $bin = $this->locateBinary('semgrep');
        if ($bin === null || empty($paths)) {
            return null;
        }

        $cmd = [$bin, 'scan', '--json', '--quiet', '--timeout=20', '--config=auto'];
        foreach ($paths as $p) {
            $cmd[] = $p;
        }

        try {
            $proc = new Process($cmd);
            $proc->setTimeout(300);
            $proc->run();
            $out = $proc->getOutput();
            $decoded = json_decode($out, true);
            if (! is_array($decoded) || ! isset($decoded['results'])) {
                Log::warning('semgrep returned no usable JSON', ['stderr' => substr($proc->getErrorOutput(), 0, 500)]);

                return null;
            }

            $findings = [];
            foreach ($decoded['results'] as $r) {
                $sev = strtolower((string) ($r['extra']['severity'] ?? 'info'));
                $sev = match ($sev) {
                    'error' => 'high',
                    'warning' => 'medium',
                    'info' => 'info',
                    default => $sev,
                };
                $findings[] = [
                    'id' => substr(hash('sha1', ($r['check_id'] ?? '') . '|' . ($r['path'] ?? '') . '|' . ($r['start']['line'] ?? 0)), 0, 12),
                    'rule' => (string) ($r['check_id'] ?? 'semgrep'),
                    'severity' => $sev,
                    'source' => 'semgrep',
                    'file' => (string) ($r['path'] ?? ''),
                    'line' => (int) ($r['start']['line'] ?? 0),
                    'column' => (int) ($r['start']['col'] ?? 0),
                    'message' => (string) ($r['extra']['message'] ?? ''),
                    'snippet' => (string) ($r['extra']['lines'] ?? ''),
                    'cwe' => isset($r['extra']['metadata']['cwe']) ? (string) (is_array($r['extra']['metadata']['cwe']) ? $r['extra']['metadata']['cwe'][0] : $r['extra']['metadata']['cwe']) : '',
                    'owasp' => isset($r['extra']['metadata']['owasp']) ? (string) (is_array($r['extra']['metadata']['owasp']) ? $r['extra']['metadata']['owasp'][0] : $r['extra']['metadata']['owasp']) : '',
                ];
            }

            return $findings;
        } catch (\Throwable $e) {
            Log::warning('semgrep scan failed: ' . $e->getMessage());

            return null;
        }
    }

    /**
     * Language-aware regex scanner. Bounded to `self::BUILTIN_PATTERNS` —
     * narrow but high-signal. Always succeeds, never throws.
     *
     * @param  array<int, string>  $files
     * @param  array<string, array<int, string>>  $extMap
     * @return array<int, array<string, mixed>>
     */
    private function runBuiltin(array $files, array $extMap): array
    {
        $extToLang = [];
        foreach ($extMap as $lang => $exts) {
            foreach ($exts as $e) {
                $extToLang[strtolower($e)] = $lang;
            }
        }

        $findings = [];
        foreach ($files as $file) {
            $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $lang = $extToLang[$ext] ?? null;
            $patterns = self::BUILTIN_PATTERNS[$lang] ?? null;
            if ($patterns === null) {
                continue;
            }

            $lines = @file($file, FILE_IGNORE_NEW_LINES);
            if ($lines === false) {
                continue;
            }

            foreach ($lines as $idx => $line) {
                foreach ($patterns as $p) {
                    if (@preg_match($p['pattern'], $line)) {
                        $findings[] = [
                            'id' => substr(hash('sha1', $p['id'] . '|' . $file . '|' . ($idx + 1)), 0, 12),
                            'rule' => $p['id'],
                            'severity' => $p['severity'],
                            'source' => 'builtin',
                            'file' => $file,
                            'line' => $idx + 1,
                            'column' => 1,
                            'message' => $p['message'],
                            'snippet' => $this->snippet($lines, $idx, 2),
                            'recommendation' => $this->builtinRecommendation($p['id']),
                            'cwe' => $p['cwe'] ?? '',
                            'owasp' => $p['owasp'] ?? '',
                        ];
                        // One rule per line to avoid duplicate noise.
                        break;
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * AI-backed scan. Sends each file (bounded) to the LLM endpoint the Hub
     * advertised via heartbeat (ollama or vllm). Returns zero findings if
     * the endpoint is not configured or unreachable — never blocks the
     * compliance report.
     *
     * @param  array<int, string>  $files
     * @param  array<string, mixed>  $cfg
     * @return array<int, array<string, mixed>>
     */
    private function runAiScan(array $files, array $cfg): array
    {
        [$url, $model, $provider] = $this->resolveAiEndpoint($cfg);
        if ($url === null) {
            Log::info('Code scan: AI provider URL not configured, skipping AI sub-scan');

            return [];
        }

        $findings = [];
        $maxFiles = (int) ($cfg['addons']['code_scan_ai_max_files'] ?? 40);

        // Prioritize files likely to contain HTTP entry points / data access.
        $files = $this->prioritizeAiTargets($files, $maxFiles);

        foreach ($files as $file) {
            $body = @file_get_contents($file);
            if ($body === false || strlen($body) > 48 * 1024) {
                continue;
            }

            $prompt = $this->buildAiPrompt($file, $body);

            try {
                $raw = $this->callLlmJson($url, $model, $prompt, 60);
                if ($raw === null) {
                    continue;
                }
                $parsed = $this->parseAiJson($raw);
                foreach ($parsed as $f) {
                    $findings[] = [
                        'id' => substr(hash('sha1', ($f['rule'] ?? 'ai') . '|' . $file . '|' . ($f['line'] ?? 0)), 0, 12),
                        'rule' => (string) ($f['rule'] ?? 'ai.finding'),
                        'severity' => $this->normalizeSeverity((string) ($f['severity'] ?? 'medium')),
                        'source' => 'ai',
                        'file' => $file,
                        'line' => (int) ($f['line'] ?? 0),
                        'column' => 0,
                        'message' => (string) ($f['message'] ?? ''),
                        'snippet' => (string) ($f['snippet'] ?? ''),
                        'recommendation' => (string) ($f['recommendation'] ?? ''),
                        'ai_explanation' => (string) ($f['explanation'] ?? ''),
                        'cwe' => (string) ($f['cwe'] ?? ''),
                        'owasp' => (string) ($f['owasp'] ?? ''),
                    ];
                }
            } catch (\Throwable $e) {
                Log::debug('AI code scan failed for ' . $file . ': ' . $e->getMessage());
            }
        }

        return $findings;
    }

    /**
     * Merge + dedupe two finding lists. A finding is considered duplicate
     * when rule/file/line collide.
     *
     * @param  array<int, array<string, mixed>>  $a
     * @param  array<int, array<string, mixed>>  $b
     * @return array<int, array<string, mixed>>
     */
    private function mergeFindings(array $a, array $b): array
    {
        $seen = [];
        $out = [];
        foreach ([$a, $b] as $list) {
            foreach ($list as $f) {
                $key = ($f['rule'] ?? '') . '|' . ($f['file'] ?? '') . '|' . ($f['line'] ?? 0);
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $out[] = $f;
            }
        }

        return $out;
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * @return array{critical:int,high:int,medium:int,low:int,info:int}
     */
    private function summarize(array $findings): array
    {
        $out = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
        foreach ($findings as $f) {
            $sev = strtolower((string) ($f['severity'] ?? 'info'));
            if (! isset($out[$sev])) {
                $sev = 'info';
            }
            $out[$sev]++;
        }

        return $out;
    }

    /**
     * @param  array<int, string>  $lines
     */
    private function snippet(array $lines, int $idx, int $radius): string
    {
        $start = max(0, $idx - $radius);
        $end = min(count($lines) - 1, $idx + $radius);
        $out = [];
        for ($i = $start; $i <= $end; $i++) {
            $marker = $i === $idx ? '>' : ' ';
            $out[] = sprintf('%s %4d | %s', $marker, $i + 1, $lines[$i]);
        }

        return implode("\n", $out);
    }

    private function builtinRecommendation(string $ruleId): string
    {
        return match ($ruleId) {
            'php.sqli.concat', 'py.sql.concat', 'go.sql.concat' => '改用參數化查詢（prepared statement / bindings）。',
            'php.rce.eval', 'js.rce.eval', 'js.rce.newfunction', 'py.rce.eval' => '移除動態 eval，改以白名單 dispatch 或設定檔驅動。',
            'php.rce.shell', 'py.rce.shell', 'go.rce.exec' => '改用陣列 argv 呼叫（escapeshellarg / subprocess.run with list / exec.Command 分離參數），並驗證白名單。',
            'php.xss.echo', 'js.xss.innerhtml' => '對所有動態輸出使用 htmlspecialchars / DOM textContent / 框架內建 escape。',
            'php.file.include' => '不要用使用者輸入做 include；改以白名單對映到已知模組檔名。',
            'php.secret.hardcoded', 'js.secret.hardcoded' => '改由 .env / secret manager 讀取；並輪替已外洩之憑證。',
            'php.deserialize.unsafe', 'py.deserialize.pickle' => '避免反序列化不信任輸入；改用 JSON / protobuf 並做 schema 驗證。',
            default => '依弱點描述重構程式碼並補上測試。',
        };
    }

    private function locateBinary(string $name): ?string
    {
        $paths = ['/usr/local/bin', '/usr/bin', '/opt/homebrew/bin'];
        foreach ($paths as $p) {
            $candidate = $p . DIRECTORY_SEPARATOR . $name;
            if (is_executable($candidate)) {
                return $candidate;
            }
        }

        $which = @shell_exec('command -v ' . escapeshellarg($name) . ' 2>/dev/null');
        if (is_string($which) && trim($which) !== '' && is_executable(trim($which))) {
            return trim($which);
        }

        return null;
    }

    /**
     * @param  array<int, string>  $files
     * @return array<int, string>
     */
    private function prioritizeAiTargets(array $files, int $max): array
    {
        if (count($files) <= $max) {
            return $files;
        }

        $priority = ['Controller', 'controller', 'route', 'handler', 'api', 'auth', 'login'];
        usort($files, function ($a, $b) use ($priority) {
            $score = fn ($p) => array_sum(array_map(fn ($k) => stripos($p, $k) !== false ? 1 : 0, $priority));

            return $score($b) <=> $score($a);
        });

        return array_slice($files, 0, $max);
    }

    private function buildAiPrompt(string $file, string $body): string
    {
        $lang = pathinfo($file, PATHINFO_EXTENSION);
        $kb = CodeScanKnowledgeBase::forFile($file, $body);

        $lines = [
            'You are a senior application-security engineer. Review the source code below and identify REAL security vulnerabilities (OWASP Top 10 / CWE Top 25).',
            '',
            'Use the framework context below as ground truth — do NOT flag items listed as "safe idioms" and DO treat listed "tainted sources" as reaching any "dangerous sinks" they flow into.',
            '',
            $kb,
            '',
            'Respond with ONLY valid JSON matching this schema:',
            '{"findings":[{"rule":"<short-id>","severity":"critical|high|medium|low|info","line":<int>,"message":"<one-sentence finding>","snippet":"<offending snippet>","recommendation":"<fix>","explanation":"<why this is a vuln in THIS code>","cwe":"CWE-<id>","owasp":"A<xx>:2021"}]}',
            'Rules:',
            '- Every finding MUST cite a specific line that exists in the file.',
            '- If the file is clearly safe, return {"findings":[]}.',
            '- Do NOT invent CWE ids; use those from the glossary.',
            '- Do NOT restate safe idioms as vulnerabilities.',
            '',
            '--- file: ' . $file . ' ---',
            '--- language: ' . $lang . ' ---',
            $this->annotateLines($body),
        ];

        return implode("\n", $lines);
    }

    /**
     * Prefix each source line with its line number so the model can cite
     * exact locations and so self-verification can cross-check easily.
     */
    private function annotateLines(string $body): string
    {
        $lines = explode("\n", $body);
        $out = [];
        foreach ($lines as $i => $line) {
            $out[] = sprintf('%4d| %s', $i + 1, $line);
        }

        return implode("\n", $out);
    }

    /* ------------------------------------------------------------------ */
    /* AI Stage 2 — triage rule-based findings                             */
    /* ------------------------------------------------------------------ */

    /**
     * Group rule-based findings by file and ask the model to classify each
     * as true-positive / false-positive / uncertain in the context of the
     * actual surrounding code.
     *
     * @param  array<int, array<string, mixed>>  $findings
     * @param  array<string, mixed>  $cfg
     * @return array<int, array<string, mixed>>
     */
    private function triageFindings(array $findings, array $cfg): array
    {
        [$url, $model, $provider] = $this->resolveAiEndpoint($cfg);
        if ($url === null) {
            Log::info('Triage skipped — AI provider URL not configured');

            return $findings;
        }

        // Group by file so we send one request per file with all its findings.
        $byFile = [];
        foreach ($findings as $i => $f) {
            $byFile[$f['file'] ?? ''][] = ['idx' => $i, 'f' => $f];
        }

        // Cap total triage calls to protect against runaway cost on slow
        // backends. Small local models (gemma-4-26B on CPU) routinely take
        // 30s+ per call, so keep the budget modest by default.
        $maxFiles = (int) ($cfg['addons']['code_scan_triage_max_files'] ?? 15);
        $maxFindingsPerFile = (int) ($cfg['addons']['code_scan_triage_max_findings_per_file'] ?? 10);
        $filesProcessed = 0;
        $deadline = microtime(true) + (float) ($cfg['addons']['code_scan_triage_budget_seconds'] ?? 120);

        foreach ($byFile as $file => $group) {
            if (! is_string($file) || $file === '' || ! is_file($file)) {
                continue;
            }
            if ($filesProcessed++ >= $maxFiles) {
                Log::info('Triage: reached max files cap', ['cap' => $maxFiles]);
                break;
            }
            if (microtime(true) >= $deadline) {
                Log::info('Triage: exhausted time budget, remaining findings left unverified');
                break;
            }

            $body = @file_get_contents($file);
            if ($body === false || strlen($body) > 128 * 1024) {
                continue;
            }

            // Trim huge finding groups — the model gets confused with too
            // many simultaneous verdicts and takes much longer.
            if (count($group) > $maxFindingsPerFile) {
                $group = array_slice($group, 0, $maxFindingsPerFile);
            }

            $verdicts = $this->requestTriage($url, $model, $file, $body, $group);
            if (empty($verdicts)) {
                continue;
            }

            foreach ($verdicts as $v) {
                $idx = (int) ($v['idx'] ?? -1);
                if (! isset($findings[$idx])) {
                    continue;
                }
                $verdict = $this->normaliseVerdict((string) ($v['verdict'] ?? 'uncertain'));
                $conf = (float) ($v['confidence'] ?? 0.5);
                $note = (string) ($v['reason'] ?? '');

                $findings[$idx]['triage_verdict'] = $verdict;
                $findings[$idx]['triage_confidence'] = max(0.0, min(1.0, $conf));
                $findings[$idx]['triage_note'] = $note;

                // Likely FPs lose severity so they don't inflate the score.
                if ($verdict === 'likely_false_positive' && $conf >= 0.7) {
                    $findings[$idx]['severity'] = 'info';
                }
            }
        }

        return $findings;
    }

    /**
     * @param  array<int, array{idx:int, f:array<string, mixed>}>  $group
     * @return array<int, array<string, mixed>>
     */
    private function requestTriage(string $url, string $model, string $file, string $body, array $group): array
    {
        $kb = CodeScanKnowledgeBase::forFile($file, $body);
        $lines = explode("\n", $body);

        // Build a per-finding context window (20 lines around each hit)
        // instead of sending the whole file. Big files + small-model setups
        // would otherwise blow past 60s LLM timeouts.
        $findingsJson = [];
        $ctxByIdx = [];
        foreach ($group as $g) {
            $f = $g['f'];
            $line = max(1, (int) ($f['line'] ?? 0));
            $start = max(1, $line - 10);
            $end = min(count($lines), $line + 10);
            $ctx = [];
            for ($i = $start; $i <= $end; $i++) {
                $ctx[] = sprintf('%s %4d| %s', $i === $line ? '>' : ' ', $i, $lines[$i - 1] ?? '');
            }
            $ctxByIdx[$g['idx']] = implode("\n", $ctx);

            $findingsJson[] = [
                'idx' => $g['idx'],
                'rule' => $f['rule'] ?? '',
                'severity' => $f['severity'] ?? 'info',
                'line' => $line,
                'message' => $f['message'] ?? '',
                'source' => $f['source'] ?? 'rule',
            ];
        }

        // Concatenate only the windows rather than the entire file.
        $ctxBlock = [];
        foreach ($ctxByIdx as $idx => $ctx) {
            $ctxBlock[] = "# finding idx={$idx}:\n{$ctx}";
        }

        $prompt = implode("\n", [
            'You are triaging static-analysis findings. For each finding, decide: TRUE POSITIVE (real exploitable vuln), LIKELY FALSE POSITIVE (pattern matched but safe in context), or UNCERTAIN.',
            '',
            'Use the framework context to recognise safe idioms:',
            '',
            $kb,
            '',
            'Output ONLY JSON: {"verdicts":[{"idx":<int>,"verdict":"true_positive|likely_false_positive|uncertain","confidence":<0..1>,"reason":"<one sentence>"}]}',
            '',
            '--- findings ---',
            json_encode($findingsJson, JSON_UNESCAPED_UNICODE),
            '',
            '--- file: ' . $file . ' ---',
            implode("\n\n", $ctxBlock),
        ]);

        $raw = $this->callLlmJson($url, $model, $prompt, 90);
        if ($raw === null) {
            return [];
        }
        $decoded = $this->parseAiObject($raw);

        return is_array($decoded['verdicts'] ?? null) ? $decoded['verdicts'] : [];
    }

    /* ------------------------------------------------------------------ */
    /* AI Stage 3 — self-verify AI findings                                */
    /* ------------------------------------------------------------------ */

    /**
     * Send each AI finding back (with surrounding source) and ask the model
     * to confirm it cites real code at the stated line. Hallucinated
     * findings get dropped outright.
     *
     * @param  array<int, array<string, mixed>>  $findings
     * @param  array<string, mixed>  $cfg
     * @return array<int, array<string, mixed>>
     */
    private function verifyAiFindings(array $findings, array $cfg): array
    {
        [$url, $model, $provider] = $this->resolveAiEndpoint($cfg);
        if ($url === null) {
            return $findings;
        }

        $byFile = [];
        foreach ($findings as $i => $f) {
            $byFile[$f['file'] ?? ''][] = ['idx' => $i, 'f' => $f];
        }

        $maxFiles = (int) ($cfg['addons']['code_scan_verify_max_files'] ?? 50);
        $filesProcessed = 0;
        $keep = [];

        foreach ($byFile as $file => $group) {
            if ($filesProcessed++ >= $maxFiles || ! is_string($file) || ! is_file($file)) {
                // Conservatively keep unverified findings but mark them.
                foreach ($group as $g) {
                    $f = $g['f'];
                    $f['triage_verdict'] = $f['triage_verdict'] ?? 'unverified';
                    $keep[] = $f;
                }
                continue;
            }

            $body = @file_get_contents($file);
            if ($body === false || strlen($body) > 48 * 1024) {
                foreach ($group as $g) {
                    $keep[] = $g['f'];
                }
                continue;
            }

            $verdicts = $this->requestVerify($url, $model, $file, $body, $group);
            $verdictByIdx = [];
            foreach ($verdicts as $v) {
                $verdictByIdx[(int) ($v['idx'] ?? -1)] = $v;
            }

            foreach ($group as $g) {
                $f = $g['f'];
                $v = $verdictByIdx[$g['idx']] ?? null;
                if ($v === null) {
                    $f['triage_verdict'] = 'unverified';
                    $keep[] = $f;
                    continue;
                }

                $verdict = $this->normaliseVerdict((string) ($v['verdict'] ?? 'uncertain'));
                $conf = (float) ($v['confidence'] ?? 0.5);
                $note = (string) ($v['reason'] ?? '');

                // Drop outright-hallucinated findings (model can't find the
                // cited code or admits it was wrong).
                if ($verdict === 'hallucinated' && $conf >= 0.6) {
                    Log::debug('Dropped hallucinated AI finding', ['file' => $file, 'rule' => $f['rule'] ?? '', 'reason' => $note]);
                    continue;
                }

                $f['triage_verdict'] = $verdict === 'hallucinated' ? 'uncertain' : $verdict;
                $f['triage_confidence'] = max(0.0, min(1.0, $conf));
                $f['triage_note'] = $note;
                if ($verdict === 'likely_false_positive' && $conf >= 0.7) {
                    $f['severity'] = 'info';
                }
                $keep[] = $f;
            }
        }

        return $keep;
    }

    /**
     * @param  array<int, array{idx:int, f:array<string, mixed>}>  $group
     * @return array<int, array<string, mixed>>
     */
    private function requestVerify(string $url, string $model, string $file, string $body, array $group): array
    {
        $annotated = $this->annotateLines($body);

        $findingsJson = [];
        foreach ($group as $g) {
            $f = $g['f'];
            $findingsJson[] = [
                'idx' => $g['idx'],
                'rule' => $f['rule'] ?? '',
                'severity' => $f['severity'] ?? 'info',
                'line' => (int) ($f['line'] ?? 0),
                'message' => $f['message'] ?? '',
                'cited_snippet' => $f['snippet'] ?? '',
            ];
        }

        $prompt = implode("\n", [
            'You are cross-checking AI-generated vulnerability findings for accuracy. For each finding, verify that:',
            '  1. The cited line number corresponds to code that actually matches the described issue.',
            '  2. The CWE/severity is plausible for that code.',
            '  3. The finding is not a duplicate, over-general, or based on a hallucinated snippet.',
            '',
            'Mark a finding as:',
            '  - "true_positive" if you can point to the exact dangerous code at the cited line.',
            '  - "hallucinated" if the cited line does not contain what the finding claims (drop these).',
            '  - "likely_false_positive" if the code exists but is actually safe in context.',
            '  - "uncertain" if you cannot verify without more context.',
            '',
            'Respond with ONLY valid JSON: {"verdicts":[{"idx":<int>,"verdict":"true_positive|likely_false_positive|hallucinated|uncertain","confidence":<0..1>,"reason":"<one sentence>"}]}',
            '',
            '--- findings to verify ---',
            json_encode($findingsJson, JSON_UNESCAPED_UNICODE),
            '',
            '--- file: ' . $file . ' ---',
            $annotated,
        ]);

        $raw = $this->callLlmJson($url, $model, $prompt, 90);
        if ($raw === null) {
            return [];
        }
        $decoded = $this->parseAiObject($raw);

        return is_array($decoded['verdicts'] ?? null) ? $decoded['verdicts'] : [];
    }

    /**
     * Parse a top-level JSON object from the LLM response, stripping markdown
     * fences the model may have added despite `format=json`.
     *
     * @return array<string, mixed>
     */
    private function parseAiObject(string $raw): array
    {
        $raw = trim($raw);
        if ($raw === '') {
            return [];
        }
        $raw = preg_replace('/^```(?:json)?\s*|\s*```$/m', '', $raw) ?: $raw;
        $decoded = json_decode($raw, true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Fast probe — does the LLM endpoint answer a TCP connection within
     * 1 second? Skips AI stages entirely when it doesn't, rather than
     * waste per-finding-request timeouts on an unreachable host.
     *
     * @param  array<string, mixed>  $cfg
     */
    private function isAiReachable(array $cfg): bool
    {
        [$url,, ] = $this->resolveAiEndpoint($cfg);
        if ($url === null) {
            return false;
        }
        $parts = parse_url($url);
        if (empty($parts['host'])) {
            return false;
        }
        $port = (int) ($parts['port'] ?? (($parts['scheme'] ?? 'http') === 'https' ? 443 : 80));

        $errno = 0;
        $errstr = '';
        $fp = @fsockopen($parts['host'], $port, $errno, $errstr, 1.0);
        if ($fp === false) {
            Log::info('AI endpoint unreachable, skipping triage/verify', [
                'host' => $parts['host'],
                'port' => $port,
                'err' => $errstr,
            ]);

            return false;
        }
        fclose($fp);

        return true;
    }

    /**
     * Resolve the AI endpoint from synced Hub config. Returns [url, model,
     * provider]. `url` is null when no endpoint is reachable at all.
     *
     * When the configured provider is vLLM / llama.cpp (or any OpenAI-
     * compatible gateway) and model is blank, the caller should query
     * `/v1/models` to auto-pick — see `discoverModel()`.
     *
     * @param  array<string, mixed>  $cfg
     * @return array{0:?string,1:string,2:string}
     */
    private function resolveAiEndpoint(array $cfg): array
    {
        $provider = (string) ($cfg['ai_provider'] ?? 'ollama');
        $url = $cfg[$provider]['url'] ?? null;
        $model = $cfg[$provider]['model'] ?? null;

        // Fallback chain: configured provider → ollama → vllm.
        if (empty($url)) {
            $url = $cfg['ollama']['url'] ?? $cfg['vllm']['url'] ?? null;
            $model = $model ?: ($cfg['ollama']['model'] ?? $cfg['vllm']['model'] ?? null);
        }

        if (empty($url)) {
            return [null, '', $provider];
        }

        // Substitute host.docker.internal → 127.0.0.1 when running on the
        // host itself (the alias only resolves inside Docker). This covers
        // the very common case where the WAF admin set the URL from within
        // the Hub container but the agent runs directly on the OS.
        $url = $this->rewriteHostDockerInternal((string) $url);

        // If the model is blank and the provider is OpenAI-compatible (vLLM /
        // llama.cpp / LM Studio), ask the server which model it has loaded.
        // Cached so we only do this once per scan run.
        $model = (string) ($model ?? '');
        if ($model === '' && $this->isOpenAiStyle($url, $provider)) {
            $model = $this->discoverModel($url) ?: '';
        }

        return [$url, $model, $provider];
    }

    /**
     * If the URL uses the Docker-only `host.docker.internal` alias but we're
     * running outside Docker where that name has no resolver entry, rewrite
     * it to loopback so the agent can still reach services on the same host.
     */
    private function rewriteHostDockerInternal(string $url): string
    {
        if (! str_contains($url, 'host.docker.internal')) {
            return $url;
        }
        // gethostbyname returns the input unchanged on failure.
        $resolved = @gethostbyname('host.docker.internal');
        if ($resolved === 'host.docker.internal') {
            $rewritten = str_replace('host.docker.internal', '127.0.0.1', $url);
            Log::info('Code scan: rewrote host.docker.internal to 127.0.0.1 (alias not resolvable on this host)', [
                'original' => $url,
                'rewritten' => $rewritten,
            ]);

            return $rewritten;
        }

        return $url;
    }

    /**
     * True when the endpoint should be treated as OpenAI-compatible (vLLM,
     * llama.cpp-server, LM Studio, LiteLLM, etc). We check:
     *  - explicit provider setting (`ai_provider` == vllm)
     *  - /v1 in the URL (many deployments expose it that way)
     *  - user hinted by putting "vllm" / "openai" in the provider field
     */
    private function isOpenAiStyle(string $url, string $provider): bool
    {
        $p = strtolower($provider);
        if (in_array($p, ['vllm', 'openai', 'lmstudio', 'llamacpp', 'litellm'], true)) {
            return true;
        }

        return str_contains($url, '/v1');
    }

    /**
     * Query /v1/models on an OpenAI-compatible server and return the first
     * model id. Cached per-process for 5 minutes. Returns null on failure
     * so the caller can fall back to a placeholder name.
     */
    private ?array $modelCache = null;

    private function discoverModel(string $url): ?string
    {
        if ($this->modelCache !== null && $this->modelCache['url'] === $url) {
            return $this->modelCache['model'];
        }

        $base = rtrim($url, '/');
        // Try $base/v1/models first; if $base already ends in /v1, try
        // $base/models too.
        $candidates = [];
        if (str_ends_with($base, '/v1')) {
            $candidates[] = $base . '/models';
        } else {
            $candidates[] = $base . '/v1/models';
            $candidates[] = $base . '/models';
        }

        foreach ($candidates as $endpoint) {
            try {
                $resp = Http::timeout(3)->get($endpoint);
                if (! $resp->successful()) {
                    continue;
                }
                $data = $resp->json('data') ?? $resp->json('models') ?? [];
                foreach ((array) $data as $m) {
                    $id = $m['id'] ?? $m['model'] ?? $m['name'] ?? null;
                    if (is_string($id) && $id !== '') {
                        Log::info('Code scan: auto-detected AI model', ['endpoint' => $endpoint, 'model' => $id]);
                        $this->modelCache = ['url' => $url, 'model' => $id];

                        return $id;
                    }
                }
            } catch (\Throwable $e) {
                Log::debug('discoverModel exception on ' . $endpoint . ': ' . $e->getMessage());
            }
        }

        $this->modelCache = ['url' => $url, 'model' => null];

        return null;
    }

    /**
     * Issue a JSON-mode completion request, tolerant of both Ollama
     * (/api/generate) and OpenAI-compatible (/v1/chat/completions) gateways.
     * The endpoint is picked by URL shape so vLLM / LM Studio / Ollama can
     * all be used interchangeably.
     */
    private function callLlmJson(string $url, string $model, string $prompt, int $timeout = 90): ?string
    {
        $cfg = $this->waf->getWafConfig();
        $provider = (string) ($cfg['ai_provider'] ?? 'ollama');
        $base = rtrim($url, '/');
        $isOpenAi = $this->isOpenAiStyle($url, $provider);

        try {
            if ($isOpenAi) {
                // OpenAI-compat server — append /chat/completions regardless of
                // whether the base URL ends in /v1 (many llama.cpp deployments
                // expose the /v1 prefix at the root path).
                $endpoint = str_ends_with($base, '/v1')
                    ? $base . '/chat/completions'
                    : $base . '/v1/chat/completions';

                $resp = Http::timeout($timeout)->connectTimeout(5)->post($endpoint, [
                    'model' => $model !== '' ? $model : 'default',
                    'messages' => [
                        ['role' => 'user', 'content' => $prompt],
                    ],
                    'temperature' => 0.1,
                    'max_tokens' => 1024,
                    'response_format' => ['type' => 'json_object'],
                ]);
                if (! $resp->successful()) {
                    Log::warning('LLM (openai) non-2xx', [
                        'endpoint' => $endpoint,
                        'model' => $model,
                        'status' => $resp->status(),
                        'body' => substr($resp->body(), 0, 300),
                    ]);

                    return null;
                }

                return (string) ($resp->json('choices.0.message.content') ?? '');
            }

            // Ollama native — /api/generate. Model CAN be empty on some
            // deployments but it's usually required.
            $resp = Http::timeout($timeout)->post($base . '/api/generate', [
                'model' => $model !== '' ? $model : 'sentinel-security',
                'prompt' => $prompt,
                'stream' => false,
                'format' => 'json',
            ]);
            if (! $resp->successful()) {
                Log::warning('LLM (ollama) non-2xx', [
                    'endpoint' => $base . '/api/generate',
                    'model' => $model,
                    'status' => $resp->status(),
                    'body' => substr($resp->body(), 0, 300),
                ]);

                return null;
            }

            return (string) ($resp->json('response') ?? '');
        } catch (\Throwable $e) {
            Log::warning('LLM request exception', [
                'url' => $url,
                'provider' => $provider,
                'err' => $e->getMessage(),
            ]);

            return null;
        }
    }

    private function normaliseVerdict(string $v): string
    {
        $v = strtolower(str_replace([' ', '-'], '_', trim($v)));

        return match ($v) {
            'true_positive', 'tp', 'confirmed', 'real' => 'true_positive',
            'likely_false_positive', 'false_positive', 'fp', 'safe' => 'likely_false_positive',
            'hallucinated', 'fabricated', 'invalid' => 'hallucinated',
            default => 'uncertain',
        };
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function parseAiJson(string $raw): array
    {
        $raw = trim($raw);
        if ($raw === '') {
            return [];
        }
        // Strip markdown fences if the model added them despite format=json.
        $raw = preg_replace('/^```(?:json)?\s*|\s*```$/m', '', $raw) ?: $raw;

        $decoded = json_decode($raw, true);
        if (! is_array($decoded)) {
            return [];
        }

        $list = $decoded['findings'] ?? (is_list($decoded) ? $decoded : []);
        if (! is_array($list)) {
            return [];
        }

        return array_values(array_filter($list, 'is_array'));
    }

    private function normalizeSeverity(string $s): string
    {
        $s = strtolower(trim($s));

        return match ($s) {
            'critical', 'high', 'medium', 'low', 'info' => $s,
            'error' => 'high',
            'warning', 'warn' => 'medium',
            'note' => 'info',
            default => 'medium',
        };
    }
}
