<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasFactory, Notifiable, HasRoles, SoftDeletes;

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    const USER_ROLES = [
        "ENTERPRENEUR" => "entrepreneur",
        "SPONSOR" => "sponsor",
        "ADMIN" => "admin",
    ];

    public static function listUserRoles(bool $asKeys = true): array
    {
        $roles = [];
        foreach (self::USER_ROLES as $key => $role) {
            $roles[$key] = ucfirst($role);
        }
        return $asKeys ? $roles : array_keys($roles);
    }

    // Relationships
    public function proposals()
    {
        return $this->hasMany(Proposal::class);
    }

    public function sponsorships()
    {
        return $this->hasMany(Sponsorship::class);
    }

    public function escrowTransactions()
    {
        return $this->hasMany(EscrowTransaction::class, 'sponsor_id');
    }

    public function withdrawals()
    {
        return $this->hasMany(Withdrawal::class);
    }

    public function transactionLedgers()
    {
        return $this->hasMany(TransactionLedger::class);
    }

    public function notifications()
    {
        return $this->hasMany(Notification::class);
    }

    public function stories()
    {
        return $this->hasMany(Storie::class);
    }
}
