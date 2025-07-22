<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Notification extends Model
{
    protected $guarded = [];

    const NOTIFICATION_STATUSES = [
        'unread' => 'unread',
        'read' => 'read',
    ];

    public static function listNotificationStatuses(bool $asKeys = true): array
    {
        $statuses = [];
        foreach (self::NOTIFICATION_STATUSES as $key => $status) {
            $statuses[$key] = ucfirst($status);
        }
        return $asKeys ? $statuses : array_keys($statuses);
    }
}
