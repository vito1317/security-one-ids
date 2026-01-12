<?php

namespace App\Services\Detection;

use App\Models\IdsSignature;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;

/**
 * Signature Detection Engine
 * 
 * Detects attacks using signature-based pattern matching
 */
class SignatureEngine
{
    private Collection $signatures;
    private bool $cacheLoaded = false;

    public function __construct()
    {
        $this->signatures = collect([]);
    }

    /**
     * Load signatures from database with caching
     */
    private function loadSignatures(): void
    {
        if ($this->cacheLoaded) {
            return;
        }

        $this->signatures = IdsSignature::where('enabled', true)
            ->orderBy('severity', 'desc')
            ->get();

        $this->cacheLoaded = true;
    }

    /**
     * Analyze log data for attack signatures
     *
     * @param array $logData Parsed log entry
     * @return array|null Detection result or null if no match
     */
    public function analyze(array $logData): ?array
    {
        $this->loadSignatures();

        $uri = $logData['uri']['full'] ?? '';
        $userAgent = $logData['user_agent'] ?? '';
        $method = $logData['method'] ?? '';

        foreach ($this->signatures as $signature) {
            // Check where to apply the signature
            $matchLocations = $this->getMatchLocations($signature, $logData);
            
            foreach ($matchLocations as $location => $value) {
                if ($this->matchesPattern($signature->pattern, $value)) {
                    return [
                        'detected' => true,
                        'signature_id' => $signature->id,
                        'signature_name' => $signature->name,
                        'category' => $signature->category,
                        'severity' => $signature->severity,
                        'matched_location' => $location,
                        'matched_value' => substr($value, 0, 200), // Truncate for logging
                        'pattern' => $signature->pattern,
                        'description' => $signature->description,
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Get locations to check for pattern matching
     */
    private function getMatchLocations(IdsSignature $signature, array $logData): array
    {
        $locations = [];

        // Check URI
        if ($signature->match_uri && isset($logData['uri']['full'])) {
            $locations['uri'] = $logData['uri']['full'];
        }

        // Check User-Agent
        if ($signature->match_user_agent && isset($logData['user_agent'])) {
            $locations['user_agent'] = $logData['user_agent'];
        }

        // Check Referer
        if ($signature->match_referer && isset($logData['referer'])) {
            $locations['referer'] = $logData['referer'];
        }

        return $locations;
    }

    /**
     * Match pattern against value
     */
    private function matchesPattern(string $pattern, string $value): bool
    {
        // Case-insensitive match
        return @preg_match('/' . $pattern . '/i', $value) === 1;
    }

    /**
     * Analyze batch of logs
     *
     * @param Collection $logs
     * @return Collection Detection results
     */
    public function analyzeBatch(Collection $logs): Collection
    {
        return $logs->map(function ($log) {
            $result = $this->analyze($log);
            if ($result) {
                $result['log_data'] = $log;
            }
            return $result;
        })->filter();
    }

    /**
     * Get all enabled signatures
     */
    public function getSignatures(): Collection
    {
        $this->loadSignatures();
        return $this->signatures;
    }

    /**
     * Built-in signature patterns
     */
    public static function getBuiltInSignatures(): array
    {
        return [
            // SQL Injection
            [
                'name' => 'SQL Injection - UNION Based',
                'description' => 'Detects UNION-based SQL injection attempts',
                'pattern' => '(union\s+.+\s+select|select\s+.+\s+from)',
                'category' => 'sqli',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'SQL Injection - Boolean Based',
                'description' => 'Detects boolean-based blind SQL injection',
                'pattern' => "('\s*(or|and)\s*'?\d*\s*[=<>]+\s*'?\d*|or\s+1\s*=\s*1)",
                'category' => 'sqli',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'SQL Injection - Comment Injection',
                'description' => 'Detects SQL comment-based injection',
                'pattern' => '(--|#|\/\*|\*\/)',
                'category' => 'sqli',
                'severity' => 'high',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'SQL Injection - DROP/DELETE',
                'description' => 'Detects destructive SQL commands',
                'pattern' => '(drop\s+table|delete\s+from|truncate\s+table)',
                'category' => 'sqli',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'SQL Injection - Time Based',
                'description' => 'Detects time-based blind SQL injection',
                'pattern' => '(waitfor\s+delay|sleep\s*\(|benchmark\s*\()',
                'category' => 'sqli',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],

            // XSS
            [
                'name' => 'XSS - Script Tag',
                'description' => 'Detects HTML script tag injection',
                'pattern' => '<script[^>]*>',
                'category' => 'xss',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => true,
                'enabled' => true,
            ],
            [
                'name' => 'XSS - Event Handler',
                'description' => 'Detects JavaScript event handler injection',
                'pattern' => 'on(load|error|click|mouse|focus|blur|submit|change|keyup|keydown)\s*=',
                'category' => 'xss',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => true,
                'enabled' => true,
            ],
            [
                'name' => 'XSS - JavaScript Protocol',
                'description' => 'Detects javascript: protocol usage',
                'pattern' => 'javascript\s*:',
                'category' => 'xss',
                'severity' => 'high',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => true,
                'enabled' => true,
            ],
            [
                'name' => 'XSS - SVG/IMG/IFRAME Tags',
                'description' => 'Detects XSS via SVG, IMG, IFRAME tags',
                'pattern' => '<(svg|img|iframe|body|embed|object)[^>]*',
                'category' => 'xss',
                'severity' => 'high',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => true,
                'enabled' => true,
            ],
            [
                'name' => 'XSS - Alert/Confirm/Prompt',
                'description' => 'Detects JavaScript dialog functions',
                'pattern' => '(alert|confirm|prompt)\s*\(',
                'category' => 'xss',
                'severity' => 'high',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => true,
                'enabled' => true,
            ],

            // Path Traversal / LFI
            [
                'name' => 'Path Traversal - Directory Traversal',
                'description' => 'Detects directory traversal attempts',
                'pattern' => '(\.\.\/|\.\.\\\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e)',
                'category' => 'lfi',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'Path Traversal - Unix System Files',
                'description' => 'Detects attempts to access Unix system files',
                'pattern' => '(etc\/passwd|etc\/shadow|etc\/hosts|etc\/group|proc\/|sys\/)',
                'category' => 'lfi',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'Path Traversal - Windows System Files',
                'description' => 'Detects attempts to access Windows system files',
                'pattern' => '(windows\\\\system32|boot\.ini|win\.ini|system32\\\\config)',
                'category' => 'lfi',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'Path Traversal - PHP Wrappers',
                'description' => 'Detects PHP stream wrapper attacks',
                'pattern' => '(php:\/\/|data:\/\/|expect:\/\/|phar:\/\/)',
                'category' => 'lfi',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'Path Traversal - Null Byte',
                'description' => 'Detects null byte injection',
                'pattern' => '(%00|\\x00)',
                'category' => 'lfi',
                'severity' => 'high',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],

            // Command Injection / RCE
            [
                'name' => 'Command Injection - Shell Operators',
                'description' => 'Detects shell command injection attempts',
                'pattern' => '(;\s*\w|(\||&){1,2}\s*\w|`[^`]+`|\$\(|\$\{)',
                'category' => 'rce',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'Command Injection - System Commands',
                'description' => 'Detects common system command usage',
                'pattern' => '([\s;|&](cat|ls|pwd|whoami|wget|curl|nc|bash|sh|id|uname|netcat|python|perl|ruby|php)[\s(])',
                'category' => 'rce',
                'severity' => 'high',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'Command Injection - Reverse Shell',
                'description' => 'Detects reverse shell attempts',
                'pattern' => '(nc\s+-[elp]|bash\s+-i|\/dev\/tcp\/|mkfifo|ncat|socat)',
                'category' => 'rce',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],

            // Scanning Tools
            [
                'name' => 'Scanner Detection - SQLMap',
                'description' => 'Detects SQLMap automated SQL injection tool',
                'pattern' => 'sqlmap',
                'category' => 'scanner',
                'severity' => 'high',
                'match_uri' => false,
                'match_user_agent' => true,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'Scanner Detection - Nikto',
                'description' => 'Detects Nikto web scanner',
                'pattern' => 'nikto',
                'category' => 'scanner',
                'severity' => 'high',
                'match_uri' => false,
                'match_user_agent' => true,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'Scanner Detection - Nmap',
                'description' => 'Detects Nmap network scanner',
                'pattern' => 'nmap',
                'category' => 'scanner',
                'severity' => 'high',
                'match_uri' => false,
                'match_user_agent' => true,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'Scanner Detection - Burp Suite',
                'description' => 'Detects Burp Suite proxy/scanner',
                'pattern' => 'burp',
                'category' => 'scanner',
                'severity' => 'medium',
                'match_uri' => false,
                'match_user_agent' => true,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'Scanner Detection - Acunetix',
                'description' => 'Detects Acunetix web vulnerability scanner',
                'pattern' => 'acunetix',
                'category' => 'scanner',
                'severity' => 'high',
                'match_uri' => false,
                'match_user_agent' => true,
                'match_referer' => false,
                'enabled' => true,
            ],
            [
                'name' => 'Scanner Detection - Nessus',
                'description' => 'Detects Nessus vulnerability scanner',
                'pattern' => 'nessus',
                'category' => 'scanner',
                'severity' => 'high',
                'match_uri' => false,
                'match_user_agent' => true,
                'match_referer' => false,
                'enabled' => true,
            ],
        ];
    }
}
