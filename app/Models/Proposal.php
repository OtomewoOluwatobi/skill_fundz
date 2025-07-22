<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Proposal extends Model
{
    protected $gtuarded = [];
    
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
}