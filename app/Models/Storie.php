<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Storie extends Model
{
    protected $guarded = [];

    // Relationships
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function proposal()
    {
        return $this->belongsTo(Proposal::class);
    }
}
