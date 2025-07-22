<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use App\Models\TransactionLedger;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('transaction_ledgers', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->uuid('user_id');
            $table->enum('tx_type', TransactionLedger::listTransactionLedgerStatuses(false))
                ->default(TransactionLedger::TransactionLedger_STATUS['PLEDGE']);
            $table->text('tx_reference');
            $table->decimal('amount', 15, 2);
            $table->enum('direction', TransactionLedger::listDirections(false))
                ->default(TransactionLedger::DIRECTIONS['CREDIT']);
            $table->uuid('proposal_id')->nullable();
            $table->foreign('proposal_id')->references('id')->on('proposals');
            $table->text('note');
            $table->timestamps();
            $table->softDeletes();

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('transaction_ledgers');
    }
};
