<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class EscrowTransaction extends Model
{
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
}
