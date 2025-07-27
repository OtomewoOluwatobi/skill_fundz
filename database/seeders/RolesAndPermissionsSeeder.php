<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;
use App\Models\User;

class RolesAndPermissionsSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Reset cached roles and permissions
        app()[\Spatie\Permission\PermissionRegistrar::class]->forgetCachedPermissions();

        // Create permissions
        $permissions = [
            // User Management
            'view-users',
            'create-users',
            'edit-users',
            'delete-users',
            'manage-user-roles',
            
            // Proposal Management
            'view-proposals',
            'create-proposals',
            'edit-proposals',
            'delete-proposals',
            'approve-proposals',
            'decline-proposals',
            'view-own-proposals',
            'edit-own-proposals',
            'delete-own-proposals',
            
            // Sponsorship Management
            'view-sponsorships',
            'create-sponsorships',
            'edit-sponsorships',
            'delete-sponsorships',
            'approve-sponsorships',
            'decline-sponsorships',
            'view-own-sponsorships',
            'edit-own-sponsorships',
            
            // Escrow Transaction Management
            'view-escrow-transactions',
            'create-escrow-transactions',
            'edit-escrow-transactions',
            'delete-escrow-transactions',
            'fund-escrow',
            'release-escrow',
            'refund-escrow',
            'view-own-escrow-transactions',
            
            // Withdrawal Management
            'view-withdrawals',
            'create-withdrawals',
            'approve-withdrawals',
            'decline-withdrawals',
            'process-withdrawals',
            'view-own-withdrawals',
            
            // Transaction Ledger Management
            'view-transaction-ledgers',
            'create-transaction-ledgers',
            'edit-transaction-ledgers',
            'delete-transaction-ledgers',
            'view-own-transaction-ledgers',
            
            // Notification Management
            'view-notifications',
            'create-notifications',
            'edit-notifications',
            'delete-notifications',
            'send-notifications',
            'view-own-notifications',
            'mark-notifications-read',
            
            // Story Management
            'view-stories',
            'create-stories',
            'edit-stories',
            'delete-stories',
            'publish-stories',
            'view-own-stories',
            'edit-own-stories',
            'delete-own-stories',
            
            // Financial Management
            'view-financial-reports',
            'manage-platform-fees',
            'view-platform-analytics',
            
            // Admin Features
            'access-admin-panel',
            'manage-system-settings',
            'view-audit-logs',
            'manage-platform-content',
            
            // Dashboard Access
            'access-entrepreneur-dashboard',
            'access-sponsor-dashboard',
            'access-admin-dashboard',
        ];

        foreach ($permissions as $permission) {
            Permission::firstOrCreate(['name' => $permission]);
        }

        // Create roles and assign permissions
        
        // 1. ENTREPRENEUR ROLE
        $entrepreneurRole = Role::firstOrCreate(['name' => 'entrepreneur']);
        if (!$entrepreneurRole->hasPermissionTo('view-own-proposals')) {
            $entrepreneurRole->givePermissionTo([
                // Own Proposals
                'view-own-proposals',
                'create-proposals',
                'edit-own-proposals',
                'delete-own-proposals',
                
                // Own Stories
                'view-stories',
                'view-own-stories',
                'create-stories',
                'edit-own-stories',
                'delete-own-stories',
                
                // Own Transaction History
                'view-own-transaction-ledgers',
                'view-own-escrow-transactions',
                
                // Own Withdrawals
                'view-own-withdrawals',
                'create-withdrawals',
                
                // Own Notifications
                'view-own-notifications',
                'mark-notifications-read',
                
                // Dashboard Access
                'access-entrepreneur-dashboard',
            ]);
        }

        // 2. SPONSOR ROLE
        $sponsorRole = Role::firstOrCreate(['name' => 'sponsor']);
        if (!$sponsorRole->hasPermissionTo('view-proposals')) {
            $sponsorRole->givePermissionTo([
                // View Proposals (to sponsor)
                'view-proposals',
                
                // Own Sponsorships
                'view-own-sponsorships',
                'create-sponsorships',
                'edit-own-sponsorships',
                
                // Escrow Management
                'view-own-escrow-transactions',
                'create-escrow-transactions',
                'fund-escrow',
                'release-escrow',
                
                // Own Transaction History
                'view-own-transaction-ledgers',
                
                // Own Withdrawals
                'view-own-withdrawals',
                'create-withdrawals',
                
                // Stories
                'view-stories',
                'view-own-stories',
                'create-stories',
                'edit-own-stories',
                'delete-own-stories',
                
                // Own Notifications
                'view-own-notifications',
                'mark-notifications-read',
                
                // Dashboard Access
                'access-sponsor-dashboard',
            ]);
        }

        // 3. ADMIN ROLE
        $adminRole = Role::firstOrCreate(['name' => 'admin']);
        if (!$adminRole->hasPermissionTo('view-users')) {
            $adminRole->givePermissionTo(Permission::all()); // Admin gets all permissions
        }

        // Create default admin user (only if doesn't exist)
        $adminUser = User::firstOrCreate(
            ['email' => 'admin@skillfundz.com'],
            [
                'first_name' => 'Super',
                'last_name' => 'Admin',
                'phone_number' => '+1234567890',
                'password' => bcrypt('admin123'),
                'otp' => '000000',
                'is_verified' => true,
                'email_verified_at' => now(),
            ]
        );
        
        if (!$adminUser->hasRole('admin')) {
            $adminUser->assignRole('admin');
        }

        // Create sample entrepreneur (only if doesn't exist)
        $entrepreneur = User::firstOrCreate(
            ['email' => 'entrepreneur@skillfundz.com'],
            [
                'first_name' => 'John',
                'last_name' => 'Entrepreneur',
                'phone_number' => '+1234567891',
                'password' => bcrypt('entrepreneur123'),
                'otp' => '111111',
                'is_verified' => true,
                'email_verified_at' => now(),
            ]
        );
        
        if (!$entrepreneur->hasRole('entrepreneur')) {
            $entrepreneur->assignRole('entrepreneur');
        }

        // Create sample sponsor (only if doesn't exist)
        $sponsor = User::firstOrCreate(
            ['email' => 'sponsor@skillfundz.com'],
            [
                'first_name' => 'Jane',
                'last_name' => 'Sponsor',
                'phone_number' => '+1234567892',
                'password' => bcrypt('sponsor123'),
                'otp' => '222222',
                'is_verified' => true,
                'email_verified_at' => now(),
            ]
        );
        
        if (!$sponsor->hasRole('sponsor')) {
            $sponsor->assignRole('sponsor');
        }

        $this->command->info('Roles and permissions seeded successfully!');
        $this->command->info('Default users created:');
        $this->command->info('Admin: admin@skillfundz.com / admin123');
        $this->command->info('Entrepreneur: entrepreneur@skillfundz.com / entrepreneur123');
        $this->command->info('Sponsor: sponsor@skillfundz.com / sponsor123');
    }
}
