<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use App\Notifications\EmailVerificationNotification;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;

class EmailVerificationController extends Controller
{
    
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['verify', 'resend']]);
    }

    /**
     * Verify email address using hash
     */
    /**
     * Verifies user credentials and authentication status
     * 
     * This function validates user login credentials against the database
     * and checks if the user account is active and authorized.
     * 
     * @OA\Post(
     *     path="/api/auth/verify",
     *     summary="Verify user credentials",
     *     description="Validates user authentication credentials and returns verification status",
     *     operationId="verifyUser",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         description="User credentials for verification",
     *         @OA\JsonContent(
     *             required={"username", "password"},
     *             @OA\Property(property="username", type="string", example="john_doe"),
     *             @OA\Property(property="password", type="string", format="password", example="securePassword123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Verification successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User verified successfully"),
     *             @OA\Property(property="user_id", type="integer", example=12345)
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid credentials",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Invalid username or password")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Account disabled or unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Account is disabled")
     *         )
     *     )
     * )
     * 
     * @param string $username The username to verify
     * @param string $password The password to verify
     * @return array Returns verification result with success status and message
     * @throws Exception When database connection fails or validation errors occur
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
    /**
     * Resend a verification or notification message
     * 
     * @OA\Post(
     *     path="/resend",
     *     summary="Resend verification or notification message",
     *     description="Resends a previously sent verification email, SMS, or other notification message to the user",
     *     operationId="resend",
     *     tags={"Notifications"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="type", type="string", enum={"email", "sms"}, description="Type of message to resend"),
     *             @OA\Property(property="identifier", type="string", description="Email address or phone number to resend to")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Message resent successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Verification message resent successfully")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Bad request - Invalid parameters",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="error", type="string", example="Invalid message type or identifier")
     *         )
     *     ),
     *     @OA\Response(
     *         response=429,
     *         description="Too many requests - Rate limit exceeded",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="error", type="string", example="Rate limit exceeded. Please try again later.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Internal server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="error", type="string", example="Failed to resend message")
     *         )
     *     )
     * )
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
