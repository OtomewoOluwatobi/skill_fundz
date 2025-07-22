<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class TransactionLedger extends Model
{
    protected $guarded = [];

    const TransactionLedger_STATUS = [
        'PLEDGE' => 'pledge',
        'RELEASE' => 'release',
        'WITHDRAWAL' => 'withdrawal',
        'REFUND' => 'refund',
        'DISPUTE' => 'dispute',
    ];

    const DIRECTIONS = [
        'CREDIT' => 'credit',
        'DEBIT' => 'debit',
    ];

    public static function listTransactionLedgerStatuses(bool $asKeys = true): array
    {
        $statuses = [];
        foreach (self::TransactionLedger_STATUS as $key => $status) {
            $statuses[$key] = ucfirst($status);
        }
        return $asKeys ? $statuses : array_keys($statuses);
    }

    public static function listDirections(bool $asKeys = true): array
    {
        $directions = [];
        foreach (self::DIRECTIONS as $key => $direction) {
            $directions[$key] = ucfirst($direction);
        }
        return $asKeys ? $directions : array_keys($directions);
    }
}
