<?php

namespace App\Services;

/**
 * Framework-specific knowledge base for the code-scan RAG pipeline.
 *
 * Instead of relying on the LLM's generic OWASP knowledge, we inject concrete
 * per-framework patterns (tainted sources, dangerous sinks, safe idioms that
 * LOOK bad, known CVE classes) into the prompt. This dramatically cuts
 * false-positives on framework-native code — e.g. the model no longer flags
 * `DB::select($sql, [$id])` as SQLi once it's been told that prepared
 * bindings in the second argument are safe.
 *
 * Detection is keyword/path-based (lightweight, not a real embedding DB) —
 * good enough given the scanner is bounded to a few hundred files.
 */
class CodeScanKnowledgeBase
{
    /**
     * Per-framework pattern library.
     *
     * @var array<string, array<string, mixed>>
     */
    private const KB = [
        'laravel' => [
            'summary' => 'Laravel 10/11/12 application. MVC with Eloquent ORM, Blade templates, queued jobs, CSRF-protected routes.',
            'detect' => [
                'files' => ['artisan', 'composer.json'],
                'content' => ['Illuminate\\', 'use Illuminate\\', 'class .* extends (Controller|Model|Command)', 'namespace App\\\\'],
            ],
            'tainted_sources' => [
                'request()->input()', 'request()->get()', 'request()->all()',
                '$request->input()', '$request->all()', '$request->query()', '$request->json()',
                '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES',
                'route parameters: $id in function (Request $req, $id)',
                'Route::get("/.../{param}")', 'Input::get()',
            ],
            'dangerous_sinks' => [
                'DB::raw() / DB::statement() with concatenated strings',
                'DB::select($sql) where $sql contains user input without bindings',
                'eval(), assert($userInput)',
                'system(), exec(), shell_exec(), passthru(), proc_open() with user input',
                '{!! $x !!} in Blade (unescaped output) with tainted $x',
                'file_get_contents($userPath), include($userPath), require($userPath)',
                'unserialize($userInput)',
                'Log::info($x) where $x is user input (log injection)',
                'response()->redirect($userUrl) without url validation',
            ],
            'safe_idioms' => [
                'DB::select("SELECT * FROM users WHERE id = ?", [$id]) — parameterised, SAFE',
                'User::where("email", $email)->first() — Eloquent binding, SAFE',
                '{{ $user->name }} in Blade — auto-escaped, SAFE against XSS',
                'hash::make($password), bcrypt() — SAFE for password storage',
                'csrf_field(), @csrf — SAFE, framework-provided',
                'Validator::make($request->all(), [...]) — input validation, SAFE',
                'proc_open($cmd, $descriptors) where $cmd is a fixed string array — SAFE',
                'Http::post($url, $body) — Guzzle wrapper, SAFE if $url is trusted',
            ],
            'known_cve_classes' => [
                'CVE-2024-52301: Laravel env manipulation via register_argc_argv',
                'CVE-2022-40471: Telescope watchers exposing session data',
                'Mass assignment without $fillable/$guarded — CWE-915',
                'Unserialize in cookie/session payload — CWE-502',
            ],
        ],

        'vue' => [
            'summary' => 'Vue 3 SFC / Composition API frontend. Inertia or SPA. Usually bundled via Vite.',
            'detect' => [
                'files' => ['package.json', 'vite.config.js', 'vite.config.ts'],
                'content' => ['<script setup', 'defineProps', 'defineEmits', 'from [\'"]vue[\'"]', 'from [\'"]@inertiajs/vue3[\'"]'],
            ],
            'tainted_sources' => [
                'route().params', 'route().query',
                'useRoute().query', 'useRoute().params',
                'URL query parsed via new URLSearchParams(location.search)',
                'props coming from server-side Inertia (still tainted if originated from user)',
                'localStorage.getItem(key)', 'sessionStorage.getItem(key)',
                'window.name, document.cookie, document.referrer',
                'message event data (postMessage)',
            ],
            'dangerous_sinks' => [
                'v-html with untrusted content — XSS',
                'innerHTML = x', 'outerHTML = x', 'insertAdjacentHTML("...", x)',
                'new Function(x), eval(x)',
                '<component :is="x"> where x is user-controlled',
                'router.push(userInput) / window.location = userInput without URL validation',
                'document.write(x), setTimeout(stringArg), setInterval(stringArg)',
                '<a :href="x"> where x may be "javascript:" URL',
            ],
            'safe_idioms' => [
                '{{ value }} interpolation — auto-escaped, SAFE',
                ':src, :href, :title — attribute binding is text (still watch for javascript: URLs)',
                'Content-Security-Policy with nonce / strict-dynamic',
                'DOMPurify.sanitize() wrapping before v-html',
            ],
            'known_cve_classes' => [
                'Client-side template injection via Vue.compile(userInput) — CWE-94',
                'Open redirect via router.push(query.redirect_to) — CWE-601',
                'DOM-based XSS via v-html on markdown / rich-text input — CWE-79',
            ],
        ],

        'express' => [
            'summary' => 'Node.js Express (or Koa/Fastify) HTTP server.',
            'detect' => [
                'files' => ['package.json'],
                'content' => ['require\\([\'"]express[\'"]\\)', 'import express', 'app\\.(get|post|put|delete)\\(', 'app\\.use\\('],
            ],
            'tainted_sources' => [
                'req.body', 'req.params', 'req.query', 'req.headers', 'req.cookies',
                'req.get("X-Forwarded-For")',
                'multer file upload: req.files',
            ],
            'dangerous_sinks' => [
                'res.send(html) with unescaped user data — XSS',
                'res.redirect(userUrl) without validation — Open Redirect',
                'child_process.exec(cmdString) — Command Injection',
                'require(userPath) / fs.readFile(userPath) — Path Traversal',
                'eval(x), Function(x), vm.runInNewContext(x)',
                'JSON.parse on massive untrusted input — DoS',
                'mongoose find({$where: userInput}) — NoSQL injection',
            ],
            'safe_idioms' => [
                'express-validator / joi / zod schema validation',
                'parameterised query: db.query("SELECT * FROM u WHERE id = ?", [id])',
                'helmet() middleware for security headers',
                'child_process.execFile(path, [args]) — arg array, SAFE',
            ],
            'known_cve_classes' => [
                'Prototype pollution via qs / lodash merge — CWE-1321',
                'Path traversal via express.static(userPath) — CWE-22',
                'SSRF via user-provided URL to axios.get / fetch — CWE-918',
            ],
        ],

        'django' => [
            'summary' => 'Django web framework (Python).',
            'detect' => [
                'files' => ['manage.py', 'requirements.txt', 'pyproject.toml'],
                'content' => ['from django', 'import django', 'class Meta:', '@csrf_exempt', 'HttpResponse'],
            ],
            'tainted_sources' => [
                'request.GET', 'request.POST', 'request.FILES', 'request.COOKIES', 'request.META',
                'request.body (raw bytes)', 'kwargs in URL resolver',
            ],
            'dangerous_sinks' => [
                'cursor.execute(raw_sql) with %s-format — SQLi',
                '.raw() with f-string / .format() — SQLi',
                'render_to_string with unescaped {{ x|safe }} — XSS',
                'subprocess.Popen(cmd, shell=True) — Command Injection',
                'pickle.loads(request.body) — Unsafe Deserialization',
                'open(user_path) — Path Traversal',
            ],
            'safe_idioms' => [
                'Model.objects.filter(name=user_input) — ORM, SAFE',
                'cursor.execute("SELECT * FROM u WHERE id=%s", [user_id]) — parameterised',
                'mark_safe() only with KNOWN-safe strings',
                'django.views.decorators.csrf.csrf_protect',
            ],
            'known_cve_classes' => [
                'SSTI via user-controlled template names',
                'Open redirect in auth "next" parameter',
            ],
        ],

        'go-http' => [
            'summary' => 'Go net/http or Gin/Echo/Fiber web handler.',
            'detect' => [
                'files' => ['go.mod'],
                'content' => ['net/http', 'gin-gonic/gin', 'labstack/echo', 'gofiber/fiber'],
            ],
            'tainted_sources' => [
                'r.URL.Query().Get("x")', 'r.FormValue("x")', 'r.Header.Get("X-...")',
                'mux.Vars(r)["id"]', 'c.Param("id") in Gin',
                'json.Unmarshal(r.Body, &v) — check field types',
            ],
            'dangerous_sinks' => [
                'exec.Command(name, userArg) — untrusted first arg ⇒ Command Injection',
                'db.Query(fmt.Sprintf(...)) — SQLi',
                'template.HTML(x) on user input — XSS',
                'http.Get(userURL) without url.Parse + allowlist — SSRF',
            ],
            'safe_idioms' => [
                'db.Query("SELECT * FROM u WHERE id = $1", id) — bound param, SAFE',
                'html/template package auto-escapes — SAFE',
                'exec.Command("git", "log", "--oneline") — arg array, SAFE',
            ],
            'known_cve_classes' => [
                'SSRF to link-local / metadata endpoints — CWE-918',
                'Race condition in file writes via os.Create',
            ],
        ],
    ];

    /**
     * Universal CWE → short description map — injected alongside
     * framework-specific patterns. Helps the model emit well-formed
     * CWE ids.
     *
     * @var array<string, string>
     */
    private const CWE_GLOSSARY = [
        'CWE-22' => 'Path Traversal',
        'CWE-78' => 'OS Command Injection',
        'CWE-79' => 'Cross-Site Scripting (XSS)',
        'CWE-89' => 'SQL Injection',
        'CWE-94' => 'Code Injection',
        'CWE-98' => 'PHP File Inclusion',
        'CWE-287' => 'Improper Authentication',
        'CWE-352' => 'CSRF',
        'CWE-434' => 'Unrestricted File Upload',
        'CWE-502' => 'Deserialization of Untrusted Data',
        'CWE-601' => 'Open Redirect',
        'CWE-611' => 'XXE (XML External Entity)',
        'CWE-798' => 'Hardcoded Credentials',
        'CWE-915' => 'Mass Assignment',
        'CWE-918' => 'SSRF',
        'CWE-1321' => 'Prototype Pollution',
    ];

    /**
     * Detect the framework for a given file and return a prompt-ready
     * context string. Returns an empty string when no framework matches —
     * the AI falls back to its generic knowledge.
     */
    public static function forFile(string $filePath, string $content): string
    {
        $frameworks = self::detectFrameworks($filePath, $content);
        if (empty($frameworks)) {
            return self::cweBlock();
        }

        $blocks = [];
        foreach ($frameworks as $fw) {
            $blocks[] = self::renderFramework($fw);
        }
        $blocks[] = self::cweBlock();

        return implode("\n\n", $blocks);
    }

    /**
     * Which frameworks does this file belong to? A file can match multiple
     * (a Vue SFC that embeds server-rendered Inertia props is both 'vue'
     * and 'laravel'-adjacent).
     *
     * @return array<int, string>
     */
    private static function detectFrameworks(string $filePath, string $content): array
    {
        $matched = [];

        foreach (self::KB as $name => $fw) {
            // Extension-based quick filter: don't even consider python
            // frameworks for .php files.
            if (! self::extCompatible($filePath, $name)) {
                continue;
            }

            $score = 0;
            foreach ($fw['detect']['content'] ?? [] as $needle) {
                // Cheap check — fall back to regex only when the literal
                // isn't present.
                if (str_contains($content, $needle)) {
                    $score += 2;
                    continue;
                }
                $pattern = '/' . $needle . '/';
                if (@preg_match($pattern, '') !== false && preg_match($pattern, $content)) {
                    $score += 1;
                }
            }

            // Presence of a marker file in the same tree upgrades the score.
            foreach ($fw['detect']['files'] ?? [] as $marker) {
                if (self::hasMarkerInAncestry($filePath, $marker)) {
                    $score += 2;
                    break;
                }
            }

            if ($score >= 2) {
                $matched[] = $name;
            }
        }

        return $matched;
    }

    private static function extCompatible(string $filePath, string $framework): bool
    {
        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

        return match ($framework) {
            'laravel' => in_array($ext, ['php', 'phtml', 'blade.php'], true),
            'vue' => in_array($ext, ['vue', 'js', 'ts', 'jsx', 'tsx', 'mjs'], true),
            'express' => in_array($ext, ['js', 'mjs', 'cjs', 'ts', 'tsx'], true),
            'django' => $ext === 'py',
            'go-http' => $ext === 'go',
            default => true,
        };
    }

    /**
     * Walk up to 8 levels above the file looking for a marker (composer.json,
     * go.mod, etc). Cheap ancestor check — acceptable given bounded file set.
     */
    private static function hasMarkerInAncestry(string $filePath, string $marker): bool
    {
        $dir = dirname($filePath);
        for ($i = 0; $i < 8; $i++) {
            if (is_file($dir . DIRECTORY_SEPARATOR . $marker)) {
                return true;
            }
            $parent = dirname($dir);
            if ($parent === $dir) {
                break;
            }
            $dir = $parent;
        }

        return false;
    }

    private static function renderFramework(string $name): string
    {
        $fw = self::KB[$name] ?? null;
        if (! $fw) {
            return '';
        }

        $sections = [
            '### Framework context: ' . strtoupper($name),
            $fw['summary'] ?? '',
            '',
            'Tainted sources (user-controlled):',
            self::bulletList($fw['tainted_sources'] ?? []),
            '',
            'Dangerous sinks:',
            self::bulletList($fw['dangerous_sinks'] ?? []),
            '',
            'Safe idioms (do NOT flag these as vulnerabilities):',
            self::bulletList($fw['safe_idioms'] ?? []),
            '',
            'Known CVE classes for this framework:',
            self::bulletList($fw['known_cve_classes'] ?? []),
        ];

        return implode("\n", array_filter($sections, fn ($s) => $s !== ''));
    }

    private static function cweBlock(): string
    {
        $lines = ['### CWE glossary (use these ids in your output):'];
        foreach (self::CWE_GLOSSARY as $id => $desc) {
            $lines[] = "- {$id}: {$desc}";
        }

        return implode("\n", $lines);
    }

    /**
     * @param  array<int, string>  $items
     */
    private static function bulletList(array $items): string
    {
        if (empty($items)) {
            return '- (none)';
        }

        return implode("\n", array_map(fn ($i) => '- ' . $i, $items));
    }
}
