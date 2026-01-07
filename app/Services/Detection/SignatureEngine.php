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
                'pattern' => '(or|and)\s+[\'"\d]+\s*[=<>]+\s*[\'"\d]+',
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

            // XSS
            [
                'name' => 'XSS - Script Tag',
                'description' => 'Detects HTML script tag injection',
                'pattern' => '<script[^>]*>.*?<\/script>',
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
                'pattern' => 'on(load|error|click|mouse|focus|blur)\s*=',
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

            // Path Traversal
            [
                'name' => 'Path Traversal - Directory Traversal',
                'description' => 'Detects directory traversal attempts',
                'pattern' => '(\.\./|\.\.\\\\|%2e%2e[/\\\\])',
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
                'pattern' => '(/etc/(passwd|shadow|hosts|group)|/proc/|/sys/)',
                'category' => 'lfi',
                'severity' => 'critical',
                'match_uri' => true,
                'match_user_agent' => false,
                'match_referer' => false,
                'enabled' => true,
            ],

            // Command Injection
            [
                'name' => 'Command Injection - Shell Operators',
                'description' => 'Detects shell command injection attempts',
                'pattern' => '(\||;|`|\$\(|\$\{)',
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
                'pattern' => '(cat|ls|pwd|whoami|wget|curl|nc|bash|sh)\s',
                'category' => 'rce',
                'severity' => 'high',
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
        ];
    }
}
