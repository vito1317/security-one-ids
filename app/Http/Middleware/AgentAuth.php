<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AgentAuth
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $this->extractToken($request);

        $agentTokenEnv = env('AGENT_TOKEN');
        // Fallback to config if env is strictly null or empty string, preserving '0'.
        $agentToken = (string) ($agentTokenEnv !== null && $agentTokenEnv !== '' ? $agentTokenEnv : (config('ids.agent_token') ?? ''));

        if ($agentToken === '') {
            return response()->json(['error' => 'Server misconfiguration: AGENT_TOKEN is not set'], 503);
        }

        if ($token === null || $token === '' || strlen($token) !== strlen($agentToken) || !hash_equals($agentToken, $token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }

    /**
     * Safely extract and normalize the token from highest to lowest priority source.
     */
    private function extractToken(Request $request): ?string
    {
        $sources = [
            $request->bearerToken(),
            $request->header('X-Agent-Token'),
            $request->input('token'),
        ];

        foreach ($sources as $source) {
            if (is_scalar($source)) {
                $normalized = trim((string) $source);
                if ($normalized !== '') {
                    return $normalized;
                }
            }
        }

        return null;
    }
}
