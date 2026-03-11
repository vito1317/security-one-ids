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
        $token = $request->bearerToken();
        if ($token === null || $token === '') {
            $token = $request->header('X-Agent-Token');
        }
        if ($token === null || $token === '') {
            $token = $request->input('token');
        }

        $hasEnvToken = array_key_exists('AGENT_TOKEN', $_ENV) || array_key_exists('AGENT_TOKEN', $_SERVER) || getenv('AGENT_TOKEN') !== false;

        // If 'AGENT_TOKEN' exists in the environment (even as an empty string), it takes precedence
        // over the config fallback. This allows explicitly disabling or resetting the token
        // via the environment without the config overriding it.
        $agentToken = (string) ($hasEnvToken ? env('AGENT_TOKEN') : (config('ids.agent_token') ?? ''));

        if ($agentToken === '') {
            return response()->json(['error' => 'Server misconfiguration'], 500);
        }

        if (!is_scalar($token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $token = (string) $token;

        if ($token === '' || strlen($token) !== strlen($agentToken) || !hash_equals($agentToken, $token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
