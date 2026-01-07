<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\SystemUpdateController;

// System Update API (for WAF Hub to trigger updates)
Route::prefix('api')->group(function () {
    Route::post('/system/update', [SystemUpdateController::class, 'update']);
    Route::get('/system/version', [SystemUpdateController::class, 'version']);
    Route::post('/system/restart', [SystemUpdateController::class, 'restart']);
    
    // Rules update
    Route::post('/rules/update', function (\Illuminate\Http\Request $request) {
        $globalRules = $request->input('global_rules', []);
        $agentRules = $request->input('agent_rules', []);
        
        // Save rules to local storage
        $rulesPath = storage_path('app/ids_rules.json');
        file_put_contents($rulesPath, json_encode([
            'global_rules' => $globalRules,
            'agent_rules' => $agentRules,
            'updated_at' => now()->toIso8601String(),
        ], JSON_PRETTY_PRINT));
        
        \Illuminate\Support\Facades\Log::info('Rules updated via API', [
            'global_count' => count($globalRules),
            'agent_count' => count($agentRules),
        ]);
        
        return response()->json(['success' => true, 'message' => 'Rules updated']);
    });
});
