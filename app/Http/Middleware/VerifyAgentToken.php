<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class VerifyAgentToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->header('X-Agent-Token') ?? $request->bearerToken() ?? $request->input('token');
        $agentToken = (string) config('ids.agent_token', env('AGENT_TOKEN'));

        // To prevent information leakage (e.g., revealing via different response times
        // or codes that the system is misconfigured), we enforce a generic 401 response
        // for both missing configuration and invalid tokens.
        if (!is_scalar($token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $token = (string) $token;
        $configured = $agentToken !== '';
        $expectedSeed = $configured ? $agentToken : str_repeat("\0", 32);

        $tokenHash = hash('sha256', $token, true);
        $expectedHash = hash('sha256', $expectedSeed, true);
        $tokenMatches = hash_equals($expectedHash, $tokenHash);

        $isValid = $configured
            && $token !== ''
            && $tokenMatches;

        if (!$isValid) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
