<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Withdrawal extends Model
{
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
}
