<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Sponsorship extends Model
{
    protected $guarded = [];

    const SPONSORSHIP_STATUSES = [
        "PENDING" => "pending",
        "APPROVED" => "approved",
        "RELEASED" => "released",
        "DECLINED" => "declined",
    ];

    public static function listSponsorshipStatuses(bool $asKeys = true): array
    {
        $statuses = [];
        foreach (self::SPONSORSHIP_STATUSES as $key => $status) {
            $statuses[$key] = ucfirst($status);
        }
        return $asKeys ? $statuses : array_keys($statuses);
    }
}
