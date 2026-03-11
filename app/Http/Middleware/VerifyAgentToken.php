<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class VerifyAgentToken
{
    public function handle(Request $request, Closure $next)
    {
        // Ensure inputs are strictly strings to prevent "Array to string conversion" errors
        // if an attacker sends an array (e.g., ?token[]=abc) which could cause log spam.
        $rawToken = $request->input('token') ?? $request->header('X-Agent-Token') ?? $request->bearerToken();
        $token = is_string($rawToken) ? $rawToken : '';

        $rawAgentToken = config('ids.agent_token');
        $agentToken = is_string($rawAgentToken) ? $rawAgentToken : '';

        // To prevent information leakage (e.g., revealing via different response times
        // or codes that the system is misconfigured), we enforce a generic 401 response
        // for both missing configuration and invalid tokens.

        $configured = $agentToken !== '';
        $expectedSeed = $configured ? $agentToken : str_repeat("\0", 32);

        $isValid = $configured
            && $token !== ''
            && hash_equals(
                hash('sha256', $expectedSeed, true),
                hash('sha256', $token, true)
            );

        if (!$isValid) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
