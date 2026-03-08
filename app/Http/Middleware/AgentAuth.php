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
        // Prioritize non-empty tokens. If one is empty, fallback to the next.
        $extractToken = static function ($value): ?string {
            if ($value !== null && !is_scalar($value)) {
                return null;
            }

            $normalized = $value === null ? null : trim((string) $value);

            return $normalized === '' ? null : $normalized;
        };

        $token = $extractToken($request->bearerToken())
            ?? $extractToken($request->header('X-Agent-Token'))
            ?? $extractToken($request->input('token'));

        $agentToken = (string) (env('AGENT_TOKEN') ?? config('ids.agent_token') ?? '');

        if ($agentToken === '') {
            return response()->json(['error' => 'Server misconfiguration'], 503);
        }

        if ($token === null || !hash_equals($agentToken, $token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
