<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create(config('security-alerts.table', 'security_alerts'), function (Blueprint $table) {
            $table->id();
            $table->string('key')->unique();
            $table->string('ecosystem', 16);
            $table->string('package');
            $table->string('version', 64);
            $table->string('advisory_id');
            $table->text('title');
            $table->string('severity', 16);
            $table->text('link')->nullable();
            $table->string('cve', 32)->nullable()->index();
            $table->string('fixed_in', 64)->nullable();
            $table->text('affected_versions')->nullable();
            $table->boolean('dev')->default(false);
            $table->date('exploited_at')->nullable();
            $table->date('kev_due_date')->nullable();
            $table->boolean('ransomware')->default(false);
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            $table->timestamp('notified_at')->nullable();
            $table->timestamp('exploited_notified_at')->nullable();
            $table->timestamp('resolved_at')->nullable()->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(config('security-alerts.table', 'security_alerts'));
    }
};
