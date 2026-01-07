<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('ids_signatures', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->text('description')->nullable();
            $table->text('pattern'); // Regex pattern
            $table->string('category', 50); // sqli, xss, lfi, rce, scanner, etc.
            $table->enum('severity', ['critical', 'high', 'medium', 'low'])->default('medium');
            $table->boolean('match_uri')->default(true);
            $table->boolean('match_user_agent')->default(false);
            $table->boolean('match_referer')->default(false);
            $table->boolean('enabled')->default(true);
            $table->timestamps();

            $table->index('category');
            $table->index('severity');
            $table->index('enabled');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('ids_signatures');
    }
};
