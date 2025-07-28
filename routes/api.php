<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\EmailVerificationController;
use App\Http\Controllers\API\UserController;
use App\Models\User;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Authentication routes (these would typically be in a separate AuthController)
Route::post('/register', [UserController::class, 'register']);

Route::post('/login', [UserController::class, 'login']);
Route::post('/logout', [UserController::class, 'logout']);


// Email verification routes
Route::prefix('email')->group(function () {
    Route::get('/verify/{id}/{hash}', [EmailVerificationController::class, 'verify'])
        ->name('verification.verify');

    Route::post('/resend', [EmailVerificationController::class, 'resend'])
        ->middleware(['auth:api', 'throttle:6,1'])
        ->name('verification.resend');
});

// Protected routes requiring authentication
Route::middleware('auth:api')->group(function () {
    
    // User profile routes (accessible by authenticated users)
    Route::get('/profile', [UserController::class, 'profile']);
    Route::put('/profile', [UserController::class, 'updateProfile']);
    
    // Admin only routes
    Route::middleware('role:admin')->group(function () {
        Route::apiResource('users', UserController::class);
        Route::get('/users/role/{role}', [UserController::class, 'getUsersByRole']);
    });
    
    // Entrepreneur routes
    Route::middleware('role:entrepreneur')->group(function () {
        Route::get('/entrepreneur/dashboard', function () {
            return response()->json(['message' => 'Entrepreneur dashboard']);
        });
    });
    
    // Sponsor routes  
    Route::middleware('role:sponsor')->group(function () {
        Route::get('/sponsor/dashboard', function () {
            return response()->json(['message' => 'Sponsor dashboard']);
        });
    });
    
    // Routes accessible by multiple roles
    Route::middleware('role:admin,sponsor')->group(function () {
        Route::get('/proposals', function () {
            return response()->json(['message' => 'List all proposals']);
        });
    });
    
    Route::middleware('role:entrepreneur,sponsor')->group(function () {
        Route::get('/stories', function () {
            return response()->json(['message' => 'List stories']);
        });
    });
});
