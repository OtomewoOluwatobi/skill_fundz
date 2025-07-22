<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class EscrowTransaction extends Model
{
    use SoftDeletes;
    
    protected $guarded = [];

    const ESCROW_STATUSES = [
        "PLEDGED" => "pledged",
        "FUNDED" => "funded",
        "RELEASED" => "released",
        "REFUNDED" => "refunded",
        "FAILED" => "failed",
    ];

    public static function listEscrowStatuses(bool $asKeys = true): array
    {
        $statuses = [];
        foreach (self::ESCROW_STATUSES as $key => $status) {
            $statuses[$key] = ucfirst($status);
        }
        return $asKeys ? $statuses : array_keys($statuses);
    }

    // Relationships
    public function proposal()
    {
        return $this->belongsTo(Proposal::class);
    }

    public function sponsor()
    {
        return $this->belongsTo(User::class, 'sponsor_id');
    }
}
