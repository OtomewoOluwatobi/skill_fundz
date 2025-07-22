<?php

use App\Models\EscrowTransaction;
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
        Schema::create('escrow_transactions', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->uuid('proposal_id');
            $table->uuid('sponsor_id');
            $table->decimal('amount', 15, 2);
            $table->enum('status', EscrowTransaction::listEscrowStatuses(false))
                ->default(
                    EscrowTransaction::ESCROW_STATUSES['PLEDGED']
                );
            $table->text('tx_reference');
            $table->timestamp('funded_at')->nullable();
            $table->timestamp('released_at')->nullable();
            $table->timestamp('refunded_at')->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->foreign('proposal_id')
                ->references('id')
                ->on('proposals')
                ->onDelete('cascade');
            
            $table->foreign('sponsor_id')
                ->references('id')
                ->on('users')
                ->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('escrow_transactions');
    }
};
