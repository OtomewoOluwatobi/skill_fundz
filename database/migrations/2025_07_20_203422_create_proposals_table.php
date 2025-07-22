<?php

use App\Models\Proposal;
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
        Schema::create('proposals', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->uuid('user_id');
            $table->string('title');
            $table->text('description');
            $table->decimal('budget', 10, 2);
            $table->string('timeline');
            $table->text('impact');
            $table->string('video_url')->nullable();
            $table->enum('status', Proposal::listProposalStatuses(false))->default(Proposal::PROPOSAL_STATUSES['SUBMITTED']);
            $table->timestamps();
            $table->softDeletes();


            $table->foreign('user_id')
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
        Schema::dropIfExists('proposals');
    }
};
