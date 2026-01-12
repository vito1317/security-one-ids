<?php

namespace App\Console\Commands;

use App\Models\IdsSignature;
use App\Services\Detection\SignatureEngine;
use Illuminate\Console\Command;

/**
 * Seed Built-in Signatures Command
 * 
 * Populate database with built-in attack signatures
 */
class SeedSignatures extends Command
{
    protected $signature = 'ids:seed-signatures 
                            {--force : Force re-seed even if signatures exist}';

    protected $description = 'Seed database with built-in attack signatures';

    public function handle(): int
    {
        $existingCount = IdsSignature::count();

        if ($existingCount > 0 && !$this->option('force')) {
            $this->warn("Database already has {$existingCount} signatures.");
            
            if (!$this->confirm('Do you want to re-seed? This will delete existing signatures.')) {
                $this->info('Seeding cancelled.');
                return 0;
            }
        }

        if ($this->option('force') || $existingCount > 0) {
            $this->info('Clearing existing signatures...');
            IdsSignature::truncate();
        }

        $this->info('Seeding built-in signatures...');

        $signatures = SignatureEngine::getBuiltInSignatures();
        $bar = $this->output->createProgressBar(count($signatures));
        $bar->start();

        foreach ($signatures as $signature) {
            IdsSignature::create($signature);
            $bar->advance();
        }

        $bar->finish();
        $this->newLine(2);

        $this->info('Successfully seeded ' . count($signatures) . ' signatures!');

        // Display summary
        $this->newLine();
        $this->table(
            ['Category', 'Count'],
            IdsSignature::select('category')
                ->selectRaw('COUNT(*) as count')
                ->groupBy('category')
                ->get()
                ->map(fn($row) => [strtoupper($row->category), $row->count])
                ->toArray()
        );

        return 0;
    }
}
