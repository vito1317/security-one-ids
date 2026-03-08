<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class VerifyAgentToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->input('token') ?? $request->header('X-Agent-Token') ?? $request->bearerToken();
        $agentToken = (string) config('ids.agent_token', env('AGENT_TOKEN', ''));

        // To prevent length-based timing attacks, ensure both inputs are non-empty
        // and of strictly equal length before comparing them with hash_equals().
        $tokenString = (string) $token;
        if ($agentToken === '' || $tokenString === '' || strlen($agentToken) !== strlen($tokenString)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        // Use hash_equals for all comparisons to prevent timing attacks.
        if (!hash_equals($agentToken, $tokenString)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
