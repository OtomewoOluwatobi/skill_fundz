<p align="center"><a href="https://laravel.com" target="_blank"><img src="https://raw.githubusercontent.com/laravel/art/master/logo-lockup/5%20SVG/2%20CMYK/1%20Full%20Color/laravel-logolockup-cmyk-red.svg" width="400" alt="Laravel Logo"></a></p>

<p align="center">
<a href="https://github.com/laravel/framework/actions"><img src="https://github.com/laravel/framework/workflows/tests/badge.svg" alt="Build Status"></a>
<a href="https://packagist.org/packages/laravel/framework"><img src="https://img.shields.io/packagist/dt/laravel/framework" alt="Total Downloads"></a>
<a href="https://packagist.org/packages/laravel/framework"><img src="https://img.shields.io/packagist/v/laravel/framework" alt="Latest Stable Version"></a>
<a href="https://packagist.org/packages/laravel/framework"><img src="https://img.shields.io/packagist/l/laravel/framework" alt="License"></a>
</p>

## About Laravel

Laravel is a web application framework with expressive, elegant syntax. We believe development must be an enjoyable and creative experience to be truly fulfilling. Laravel takes the pain out of development by easing common tasks used in many web projects, such as:

- [Simple, fast routing engine](https://laravel.com/docs/routing).
- [Powerful dependency injection container](https://laravel.com/docs/container).
- Multiple back-ends for [session](https://laravel.com/docs/session) and [cache](https://laravel.com/docs/cache) storage.
- Expressive, intuitive [database ORM](https://laravel.com/docs/eloquent).
- Database agnostic [schema migrations](https://laravel.com/docs/migrations).
- [Robust background job processing](https://laravel.com/docs/queues).
- [Real-time event broadcasting](https://laravel.com/docs/broadcasting).

Laravel is accessible, powerful, and provides tools required for large, robust applications.

## Learning Laravel

Laravel has the most extensive and thorough [documentation](https://laravel.com/docs) and video tutorial library of all modern web application frameworks, making it a breeze to get started with the framework.

You may also try the [Laravel Bootcamp](https://bootcamp.laravel.com), where you will be guided through building a modern Laravel application from scratch.

If you don't feel like reading, [Laracasts](https://laracasts.com) can help. Laracasts contains thousands of video tutorials on a range of topics including Laravel, modern PHP, unit testing, and JavaScript. Boost your skills by digging into our comprehensive video library.

## Laravel Sponsors

We would like to extend our thanks to the following sponsors for funding Laravel development. If you are interested in becoming a sponsor, please visit the [Laravel Partners program](https://partners.laravel.com).

### Premium Partners

- **[Vehikl](https://vehikl.com)**
- **[Tighten Co.](https://tighten.co)**
- **[Kirschbaum Development Group](https://kirschbaumdevelopment.com)**
- **[64 Robots](https://64robots.com)**
- **[Curotec](https://www.curotec.com/services/technologies/laravel)**
- **[DevSquad](https://devsquad.com/hire-laravel-developers)**
- **[Redberry](https://redberry.international/laravel-development)**
- **[Active Logic](https://activelogic.com)**

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Thank you for considering contributing to the Laravel framework! The contribution guide can be found in the [Laravel documentation](https://laravel.com/docs/contributions).

## Code of Conduct

In order to ensure that the Laravel community is welcoming to all, please review and abide by the [Code of Conduct](https://laravel.com/docs/contributions#code-of-conduct).

## Security Vulnerabilities

If you discover a security vulnerability within Laravel, please send an e-mail to Taylor Otwell via [taylor@laravel.com](mailto:taylor@laravel.com). All security vulnerabilities will be promptly addressed.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Email: support@skillfundz.com
- Documentation: [API Docs](http://your-domain/api/documentation)

## License

The Laravel framework is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).

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