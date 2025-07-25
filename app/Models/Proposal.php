<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Proposal extends Model
{
    use SoftDeletes;
    
    protected $guarded = []; // Fixed typo from $gtuarded
    
    const PROPOSAL_STATUSES = [
        "SUBMITTED" => "submitted",
        "APPROVED" => "approved",
        "SPONSORED" => "sponsored",
        "DECLINED" => "declined",
    ];

    public static function listProposalStatuses(bool $asKeys = true): array
    {
        $statuses = [];
        foreach (self::PROPOSAL_STATUSES as $key => $status) {
            $statuses[$key] = ucfirst($status);
        }
        return $asKeys ? $statuses : array_keys($statuses);
    }

    // Relationships
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function escrowTransactions()
    {
        return $this->hasMany(EscrowTransaction::class);
    }

    public function transactionLedgers()
    {
        return $this->hasMany(TransactionLedger::class);
    }

    public function stories()
    {
        return $this->hasMany(Storie::class);
    }
}