<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Spatie\Permission\Traits\HasRoles;
use Tymon\JWTAuth\Contracts\JWTSubject;
use App\Notifications\EmailVerificationNotification;

class User extends Authenticatable implements JWTSubject, MustVerifyEmail
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasFactory, Notifiable, HasRoles, SoftDeletes, HasUuids;

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
        'first_name',
        'last_name',
        'phone_number',
        'email',
        'password',
        'otp',
        'is_verified',
        'email_verified_at',
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
            'is_verified' => 'boolean',
        ];
    }

    const USER_ROLES = [
        "ENTREPRENEUR" => "entrepreneur", // Fixed spelling
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

    // Role Helper Methods
    public function isEntrepreneur(): bool
    {
        return $this->hasRole('entrepreneur');
    }

    public function isSponsor(): bool
    {
        return $this->hasRole('sponsor');
    }

    public function isAdmin(): bool
    {
        return $this->hasRole('admin');
    }

    public function canManageProposal($proposal): bool
    {
        return $this->isAdmin() || 
               ($this->isEntrepreneur() && $this->id === $proposal->user_id);
    }

    public function canSponsorProposal($proposal): bool
    {
        return $this->isSponsor() && $this->id !== $proposal->user_id;
    }

    public function canViewProposal($proposal): bool
    {
        return $this->isAdmin() || 
               $this->id === $proposal->user_id || 
               $this->isSponsor();
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

    /**
     * Determine if the user has verified their email address.
     */
    public function hasVerifiedEmail(): bool
    {
        return !is_null($this->email_verified_at);
    }

    /**
     * Mark the given user's email as verified.
     */
    public function markEmailAsVerified(): bool
    {
        return $this->forceFill([
            'email_verified_at' => $this->freshTimestamp(),
            'is_verified' => true,
        ])->save();
    }

    /**
     * Send the email verification notification.
     */
    public function sendEmailVerificationNotification(): void
    {
        $this->notify(new EmailVerificationNotification($this));
    }

    /**
     * Get the email address that should be used for verification.
     */
    public function getEmailForVerification(): string
    {
        return $this->email;
    }
}
