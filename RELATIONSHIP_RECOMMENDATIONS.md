# Laravel Model Relationship Recommendations

## Current Relationship Matrix

| Model | Relationships Added |
|-------|-------------------|
| User | proposals, sponsorships, escrowTransactions, withdrawals, transactionLedgers, notifications, stories |
| Proposal | user, escrowTransactions, transactionLedgers, stories |
| Sponsorship | user |
| EscrowTransaction | proposal, sponsor |
| Withdrawal | user |
| TransactionLedger | user, proposal |
| Notification | user |
| Storie | user, proposal |

## Additional Recommendations

### 1. Polymorphic Relationships
Consider making some relationships polymorphic for better flexibility:

**Transaction Ledger** could be polymorphic to track different transaction types:
```php
// In TransactionLedger model
public function transactionable()
{
    return $this->morphTo();
}

// In EscrowTransaction model  
public function transactionLedgers()
{
    return $this->morphMany(TransactionLedger::class, 'transactionable');
}

// In Withdrawal model
public function transactionLedgers()
{
    return $this->morphMany(TransactionLedger::class, 'transactionable');
}
```

### 2. Many-to-Many Relationships
Consider if you need many-to-many relationships:

**Proposal-Sponsor Relationship**: A proposal might have multiple sponsors
```php
// Migration for pivot table
Schema::create('proposal_sponsor', function (Blueprint $table) {
    $table->uuid('proposal_id');
    $table->uuid('sponsor_id');
    $table->decimal('amount', 15, 2);
    $table->timestamps();
    
    $table->foreign('proposal_id')->references('id')->on('proposals');
    $table->foreign('sponsor_id')->references('id')->on('users');
    $table->primary(['proposal_id', 'sponsor_id']);
});

// In Proposal model
public function sponsors()
{
    return $this->belongsToMany(User::class, 'proposal_sponsor', 'proposal_id', 'sponsor_id')
                ->withPivot('amount')
                ->withTimestamps();
}

// In User model  
public function sponsoredProposals()
{
    return $this->belongsToMany(Proposal::class, 'proposal_sponsor', 'sponsor_id', 'proposal_id')
                ->withPivot('amount')
                ->withTimestamps();
}
```

### 3. Scoped Relationships
Add scoped relationships for better querying:

```php
// In User model
public function activeProposals()
{
    return $this->hasMany(Proposal::class)
                ->whereIn('status', ['submitted', 'approved']);
}

public function unreadNotifications()
{
    return $this->hasMany(Notification::class)
                ->where('status', 'unread');
}

// In Proposal model
public function fundedEscrowTransactions()
{
    return $this->hasMany(EscrowTransaction::class)
                ->where('status', 'funded');
}
```

### 4. Accessor and Mutator Improvements
Add useful accessors and mutators:

```php
// In User model
public function getFullNameAttribute()
{
    return $this->first_name . ' ' . $this->last_name;
}

// In Proposal model
public function getTotalFundedAttribute()
{
    return $this->escrowTransactions()
                ->where('status', 'funded')
                ->sum('amount');
}

// In EscrowTransaction model
protected $casts = [
    'funded_at' => 'datetime',
    'released_at' => 'datetime', 
    'refunded_at' => 'datetime',
    'amount' => 'decimal:2'
];
```

### 5. Database Optimization
Consider adding database indexes for foreign keys:

```php
// In migration files, add indexes for better performance
$table->index(['user_id', 'status']); // For filtering by user and status
$table->index(['proposal_id', 'created_at']); // For chronological queries
$table->index('created_at'); // For time-based queries
```

### 6. Model Events and Observers
Consider adding model events for business logic:

```php
// Create observers for automatic actions
php artisan make:observer ProposalObserver --model=Proposal

// In ProposalObserver
public function created(Proposal $proposal)
{
    // Send notification to admins when new proposal is created
    Notification::create([
        'user_id' => $proposal->user_id,
        'title' => 'Proposal Submitted',
        'message' => 'Your proposal "' . $proposal->title . '" has been submitted for review.',
        'status' => 'unread'
    ]);
}
```

### 7. Validation Rules
Consider adding validation rules as model properties:

```php
// In Proposal model
public static function validationRules()
{
    return [
        'title' => 'required|string|max:255',
        'description' => 'required|string',
        'budget' => 'required|numeric|min:0',
        'timeline' => 'required|string',
        'impact' => 'required|string',
        'video_url' => 'nullable|url'
    ];
}
```

### 8. Concerns for Code Organization
Create traits for shared functionality:

```php
// Create app/Models/Concerns/HasStatus.php
trait HasStatus
{
    public function scopeWithStatus($query, $status)
    {
        return $query->where('status', $status);
    }
    
    public function isStatus($status)
    {
        return $this->status === $status;
    }
}

// Use in models that have status
use App\Models\Concerns\HasStatus;

class Proposal extends Model
{
    use HasStatus;
    // ...
}
```

## Migration Best Practices Followed

✅ **Foreign Key Constraints**: All relationships have proper foreign key constraints  
✅ **Cascade Deletes**: User deletions properly cascade to related records  
✅ **Soft Deletes**: Implemented where data preservation is important  
✅ **UUID Primary Keys**: Consistent use of UUIDs for better security  
✅ **Enum Constraints**: Status fields use enums for data integrity  
✅ **Nullable Fields**: Optional relationships properly marked as nullable  

## Next Steps

1. **Test Relationships**: Create seeders to test all relationships work correctly
2. **Add Indexes**: Add database indexes for performance optimization  
3. **Create Observers**: Implement model observers for business logic
4. **Add Validation**: Create form request classes with validation rules
5. **Write Tests**: Create feature tests for relationship functionality
