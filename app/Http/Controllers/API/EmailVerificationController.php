<?php

namespace App\Http\Controllers\API;

use App\Models\User;
use App\Notifications\EmailVerificationNotification;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Routing\Controller;

class EmailVerificationController extends Controller
{
    /**
     * Verify email address using hash
     */
    public function verify(Request $request, $id, $hash): JsonResponse
    {
        try {
            /** @var User $user */
            $user = User::findOrFail($id);

            // Check if the hash matches
            if (!hash_equals($hash, sha1($user->email))) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid verification link'
                ], 400);
            }

            // Check if already verified
            if ($user->is_verified) {
                return response()->json([
                    'success' => true,
                    'message' => 'Email is already verified'
                ]);
            }

            // Mark email as verified
            $user->email_verified_at = now();
            $user->is_verified = true;
            $user->save();

            return response()->json([
                'success' => true,
                'message' => 'Email verified successfully',
                'data' => [
                    'user_id' => $user->id,
                    'email' => $user->email,
                    'verified_at' => $user->email_verified_at
                ]
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Verification failed: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Resend email verification notification
     */
    public function resend(Request $request): JsonResponse
    {
        try {
            /** @var User $user */
            $user = Auth::user();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not authenticated'
                ], 401);
            }

            if ($user->is_verified) {
                return response()->json([
                    'success' => false,
                    'message' => 'Email is already verified'
                ], 400);
            }

            // Send verification email
            $user->notify(new EmailVerificationNotification($user));

            return response()->json([
                'success' => true,
                'message' => 'Verification email sent successfully'
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to send verification email: ' . $e->getMessage()
            ], 500);
        }
    }
}
