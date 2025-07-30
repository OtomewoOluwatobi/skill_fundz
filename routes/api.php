<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\UserController;
use App\Http\Controllers\API\AdminController;
use App\Http\Controllers\API\ProposalController;

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

// Public Authentication routes (no middleware required)
Route::post('/register', [UserController::class, 'register']);
Route::post('/login', [UserController::class, 'login']);
Route::post('/forgot-password', [UserController::class, 'forgotPassword']);
Route::post('/reset-password', [UserController::class, 'resetPassword']);

// Email verification routes (public - no auth required for verify, auth required for resend)
Route::prefix('email')->name('verification.')->group(function () {
    Route::get('/verify/{id}/{hash}', [UserController::class, 'verify'])
        ->name('verify');

    Route::post('/resend', [UserController::class, 'resend'])
        ->middleware(['auth:api', 'throttle:6,1'])
        ->name('resend');
});

// Protected routes requiring authentication
Route::middleware('auth:api')->group(function () {

    // Authentication routes (require auth)
    Route::get('/logout', [UserController::class, 'logout']);

    // User profile routes (accessible by authenticated users)
    Route::get('/profile', [UserController::class, 'profile']);
    Route::put('/profile', [UserController::class, 'updateProfile']);
    Route::get('/me', [UserController::class, 'profile']); // Alias for profile

    // Proposal routes (accessible by authenticated users)
    Route::prefix('proposals')->group(function () {
        Route::get('/', [ProposalController::class, 'index']);                    // GET /api/proposals
        Route::post('/', [ProposalController::class, 'store']);                   // POST /api/proposals
        Route::get('/{proposal}', [ProposalController::class, 'show']);           // GET /api/proposals/{id}
        Route::put('/{proposal}', [ProposalController::class, 'update']);         // PUT /api/proposals/{id}
        Route::patch('/{proposal}', [ProposalController::class, 'update']);       // PATCH /api/proposals/{id}
        Route::delete('/{proposal}', [ProposalController::class, 'destroy']);     // DELETE /api/proposals/{id}
        
        // Additional proposal-specific routes
        Route::get('/user/{user}', [ProposalController::class, 'getUserProposals']); // GET user's proposals
        Route::patch('/{proposal}/status', [ProposalController::class, 'updateStatus']); // Update proposal status
    });

    // Admin only routes - User management
    Route::middleware('role:admin')->group(function () {
        // RESTful user resource routes (mapped to AdminController for proper admin functionality)
        Route::get('/users', [AdminController::class, 'index']);           // GET /api/users
        Route::post('/users', [AdminController::class, 'store']);          // POST /api/users  
        Route::get('/users/{user}', [AdminController::class, 'show']);     // GET /api/users/{id}
        Route::put('/users/{user}', [AdminController::class, 'update']);   // PUT /api/users/{id}
        Route::patch('/users/{user}', [AdminController::class, 'update']); // PATCH /api/users/{id}
        Route::delete('/users/{user}', [AdminController::class, 'destroy']); // DELETE /api/users/{id}

        // Admin management routes (if you need separate admin resource endpoints)
        Route::apiResource('admin', AdminController::class);

        // Additional user management routes
        Route::get('/users/role/{role}', [AdminController::class, 'getUsersByRole']);

        // Admin proposal management
        Route::prefix('proposals')->group(function () {
            Route::get('/all', [ProposalController::class, 'adminIndex']);        // GET all proposals (admin view)
            Route::patch('/{proposal}/approve', [ProposalController::class, 'approve']); // Approve proposal
            Route::patch('/{proposal}/reject', [ProposalController::class, 'reject']);   // Reject proposal
        });
    });
});

// Fallback route for API
Route::fallback(function () {
    return response()->json([
        'success' => false,
        'message' => 'API endpoint not found',
        'error' => 'The requested API endpoint does not exist'
    ], 404);
});
