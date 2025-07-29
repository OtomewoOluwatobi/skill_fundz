# 🚀 SkillFundz

**SkillFundz** is a comprehensive Laravel-based API platform that connects aspiring entrepreneurs with corporate and individual sponsors. Entrepreneurs can submit proposals for funding, while sponsors can pledge financial support through a secure admin-controlled **escrow system**. The platform promotes transparency, trust, and social impact in funding grassroots innovation.

---

## 🧩 Features

### 👤 User Management & Authentication
- **JWT-based Authentication**: Secure token-based authentication with login/logout endpoints
- **Role-based Access Control**: Entrepreneurs, sponsors, and admins with specific permissions
- **Email Verification**: Secure email verification system with resend functionality
- **Password Management**: Password reset via email tokens and secure password change
- **Profile Management**: Complete user profile CRUD with avatar upload support
- **OTP System**: One-time password generation for additional security

### 🔐 API Security & Documentation
- **Swagger/OpenAPI Integration**: Comprehensive API documentation with interactive testing
- **Bearer Token Authentication**: Secure API access with JWT tokens
- **Input Validation**: Robust request validation with detailed error responses
- **File Upload Security**: Secure avatar upload with file type and size validation

### 📄 Proposal System
- Create and submit project proposals with title, budget, timeline, and expected impact
- Optional video pitch or document upload support
- Track status: `submitted`, `under review`, `approved`, `sponsored`, `completed`, `declined`
- Proposal versioning and revision history

### 💸 Escrow & Payments
- Sponsors pledge funds to proposals through secure payment gateways
- Funds are held in escrow until proposals are verified and milestones met
- Admins approve release of funds or issue refunds based on project progress
- All financial activity is logged in an auditable transaction ledger
- Multi-currency support for international sponsors

### 📬 Notifications System
- **Real-time Notifications**: In-app and email notifications using Laravel's Notification system
- **Event-driven Architecture**: Automated notifications for proposal status changes, sponsor approvals, fund releases
- **Notification Preferences**: Users can customize their notification settings
- **Admin Notifications**: Automatic alerts to admins for new user registrations and critical events

### ⏲️ User Activity & Security
- `last_seen_at` tracking via middleware for user activity monitoring
- Automatic session management with configurable timeout periods
- Soft deletion of inactive accounts after configurable inactivity periods
- Comprehensive audit trails for all user actions

### 📊 Role-based Dashboards
- **Entrepreneur Dashboard**: Proposal submissions, funding status, milestone tracking, notifications
- **Sponsor Dashboard**: Funding history, impact statistics, sponsored projects overview
- **Admin Dashboard**: Complete system oversight - users, proposals, transactions, disputes, analytics

---

## ⚙️ Tech Stack

| Layer           | Technology                              |
|----------------|-----------------------------------------|
| **Backend**    | Laravel 11+ (PHP 8.2+)                |
| **API**        | RESTful API with JWT Authentication     |
| **Database**   | MySQL with UUID primary keys           |
| **Auth**       | JWT Auth + Email/OTP verification      |
| **Storage**    | Laravel Storage with avatar uploads    |
| **Validation** | Laravel Form Request Validation        |
| **Documentation** | Swagger/OpenAPI with L5-Swagger     |
| **Notifications** | Laravel Notification Channels       |
| **Queue & Jobs** | Laravel Queues + Task Scheduler      |
| **Payments**   | Paystack / Stripe / Flutterwave        |
| **Deployment** | Laravel Forge / DigitalOcean / AWS     |

---

## 🧱 Database Architecture

### Core Tables
- `users` – Entrepreneurs, sponsors, and admins with UUID primary keys
- `proposals` – Project proposals with detailed funding requirements
- `escrow_transactions` – Secure fund tracking (pledged, held, released)
- `transaction_ledger` – Comprehensive audit trail of all financial operations
- `notifications` – User notification storage and delivery tracking
- `withdrawals` – Disbursement requests and approval workflow
- `stories` – Success stories from funded projects

### Authentication & Security
- `password_reset_tokens` – Secure password reset token management
- `sessions` – User session tracking and management
- Role and permission tables via Spatie Laravel Permission

---

## 🚀 API Endpoints

### Authentication
- `POST /api/register` - User registration with role assignment
- `POST /api/login` - JWT token authentication
- `POST /api/logout` - Token invalidation
- `POST /api/forgot-password` - Password reset link generation
- `POST /api/reset-password` - Password reset with token validation

### User Profile Management
- `GET /api/profile` - Get authenticated user profile
- `PUT /api/profile` - Update user profile information
- `POST /api/change-password` - Secure password change
- `POST /api/avatar` - Avatar image upload

### Email Verification
- `GET /api/email/verify/{id}/{hash}` - Email verification via signed URL
- `POST /api/email/resend` - Resend verification email

---

## 📦 Installation & Setup

```bash
# Clone the repository
git clone https://github.com/your-username/skillfundz.git
cd skillfundz

# Install PHP dependencies
composer install

# Configure environment
cp .env.example .env
php artisan key:generate

# Generate JWT secret
php artisan jwt:secret

# Configure database and mail settings in .env
# Example:
# DB_CONNECTION=mysql
# DB_HOST=127.0.0.1
# DB_PORT=3306
# DB_DATABASE=skillfundz
# DB_USERNAME=your_username
# DB_PASSWORD=your_password

# Run database migrations
php artisan migrate

# Seed roles and permissions
php artisan db:seed --class=RolesAndPermissionsSeeder

# Generate API documentation
php artisan l5-swagger:generate

# Create storage symlink for file uploads
php artisan storage:link

# Start development server
php artisan serve
```

## 📚 API Documentation

After installation, access the interactive API documentation at:
```
http://your-domain/api/documentation
```

The Swagger UI provides:
- Complete endpoint documentation
- Request/response examples
- Interactive API testing
- Authentication token management
- File upload testing capabilities

## 🔧 Configuration

### JWT Configuration
```php
// config/jwt.php
'ttl' => env('JWT_TTL', 60), // Token lifetime in minutes
'refresh_ttl' => env('JWT_REFRESH_TTL', 20160), // Refresh token lifetime
```

### File Upload Settings
```php
// Avatar uploads: max 2MB, supported formats: jpeg, png, jpg, gif
// Stored in: storage/app/public/{user_id}/avatars/
```

### Notification Channels
- Database notifications for in-app alerts
- Email notifications for critical updates
- Configurable notification preferences per user
