<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Sponsorship extends Model
{
    use SoftDeletes, HasUuids;
    
    protected $guarded = [];

    /**
     * Indicates if the model's ID is auto-incrementing.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * The data type of the auto-incrementing ID.
     *
     * @var string
     */
    protected $keyType = 'string';

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

    // Relationships
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
