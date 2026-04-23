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

        $findings = match ($tool) {
            'ai' => $this->runAiScan($files, $cfg),
            'hybrid' => $this->mergeFindings(
                $this->runSemgrep($paths) ?? $this->runBuiltin($files, $extensions),
                $this->runAiScan($files, $cfg),
            ),
            'builtin' => $this->runBuiltin($files, $extensions),
            default => $this->runSemgrep($paths) ?? $this->runBuiltin($files, $extensions),
        };

        $summary = $this->summarize($findings);
        $duration = round(microtime(true) - $start, 2);

        return [
            'enabled' => true,
            'tool' => $tool,
            'scanned_paths' => $paths,
            'scanned_files' => count($files),
            'duration_seconds' => $duration,
            'summary' => $summary,
            'findings' => $findings,
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
            $allExt = array_merge($allExt, $exts);
        }
        $allExt = array_unique($allExt);

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
                $allowedExt[strtolower($e)] = true;
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
        $provider = $cfg['ai_provider'] ?? 'ollama';
        $url = $cfg[$provider]['url'] ?? ($cfg['ollama']['url'] ?? null);
        $model = $cfg[$provider]['model'] ?? ($cfg['ollama']['model'] ?? null);
        if (empty($url) || empty($model)) {
            Log::info('Code scan: AI provider not configured, skipping AI sub-scan');

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
                $resp = Http::timeout(60)->post(rtrim($url, '/') . '/api/generate', [
                    'model' => $model,
                    'prompt' => $prompt,
                    'stream' => false,
                    'format' => 'json',
                ]);
                if (! $resp->successful()) {
                    continue;
                }

                $raw = (string) $resp->json('response', '');
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

        return implode("\n", [
            'You are a senior application-security engineer. Review the source code below and identify real security vulnerabilities (OWASP Top 10 / CWE Top 25).',
            'Respond ONLY with JSON matching this schema:',
            '{"findings":[{"rule":"<short-id>","severity":"critical|high|medium|low|info","line":<int>,"message":"<one-sentence finding>","snippet":"<offending snippet>","recommendation":"<fix>","explanation":"<why this is a vuln>","cwe":"CWE-<id>","owasp":"A<xx>:2021"}]}',
            'If the file is clearly safe, return {"findings":[]}. Do not invent issues; cite a concrete line.',
            '--- file: ' . $file . ' ---',
            '--- language: ' . $lang . ' ---',
            $body,
        ]);
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
