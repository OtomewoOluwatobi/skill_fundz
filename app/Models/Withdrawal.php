<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Withdrawal extends Model
{
    use SoftDeletes;
    
    protected $guarded = [];

    const WITHDRAWAL_STATUSES = [
        'PENDING' => 'pending',
        'APPROVED' => 'approved',
        'COMPLETED' => 'completed',
        'FAILED' => 'failed',
    ];

    public static function listWithdrawalStatuses(bool $asKeys = true): array
    {
        $statuses = [];
        foreach (self::WITHDRAWAL_STATUSES as $key => $status) {
            $statuses[$key] = ucfirst($status);
        }
        return $asKeys ? $statuses : array_keys($statuses);
    }

    // Relationships
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
