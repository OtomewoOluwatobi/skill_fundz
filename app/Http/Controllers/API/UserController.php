<?php

namespace App\Http\Controllers\API;

use Illuminate\Routing\Controller;
use App\Models\User;
use App\Notifications\NewUserRegistered;
use App\Notifications\EmailVerificationNotification;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\Notification;
use Illuminate\Auth\Events\Verified;
use Illuminate\Support\Facades\URL;

class UserController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'forgotPassword']]);
    }

    /**
     * @OA\Post(
     *     path="/api/register",
     *     summary="Register a new user",
     *     description="Register a new user account",
     *     operationId="register",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"first_name","last_name","email","phone_number","password","role"},
     *             @OA\Property(property="first_name", type="string", example="John"),
     *             @OA\Property(property="last_name", type="string", example="Doe"),
     *             @OA\Property(property="email", type="string", format="email", example="john@example.com"),
     *             @OA\Property(property="phone_number", type="string", example="+1234567890"),
     *             @OA\Property(property="password", type="string", format="password", example="password123"),
     *             @OA\Property(property="role", type="string", enum={"entrepreneur", "sponsor"}, example="entrepreneur")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="User registered successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User registered successfully"),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="user", ref="#/components/schemas/User"),
     *                 @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Validation failed"),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */
    public function register(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'first_name'   => 'required|string|max:255',
            'last_name'    => 'required|string|max:255',
            'email'        => 'required|email|unique:users,email',
            'phone_number' => 'required|string|unique:users,phone_number',
            'password'     => 'required|string|min:8|confirmed',
            'role'         => ['required', 'string', Rule::in(array_values(User::USER_ROLES))],
            'is_verified'  => 'boolean',
        ]);

        if ($validator->fails()) {
            return $this->validationError($validator->errors());
        }

        try {
            // Create the user
            $user = User::create([
                'first_name'       => $request->first_name,
                'last_name'        => $request->last_name,
                'email'            => $request->email,
                'phone_number'     => $request->phone_number,
                'password'         => Hash::make($request->password),
                'otp'              => $this->generateOTP(),
                'is_verified'      => $request->get('is_verified', false),
                'email_verified_at' => $request->get('is_verified', false) ? now() : null,
            ]);

            // Assign role
            $user->assignRole($request->role);
            $user->load('roles');

            // Send email verification notification to the user
            if (!$user->is_verified) {
                $user->notify(new EmailVerificationNotification($user));
            }

            // Notify all admins about the new user registration
            $adminUsers = User::role('admin')->get();
            foreach ($adminUsers as $admin) {
                $admin->notify(new NewUserRegistered($user));
            }

            // Create a notification record in the database for the user
            Notification::create([
                'user_id' => $user->id,
                'title' => 'Welcome to SkillFundz!',
                'message' => 'Your account has been created successfully. Please verify your email address to get started.',
                'type' => 'welcome',
                'status' => 'unread'
            ]);

            return $this->success([
                'user' => $user,
                'message' => 'User created successfully. Verification email sent.',
                'notifications_sent' => [
                    'email_verification' => !$user->is_verified,
                    'admin_notification' => $adminUsers->count()
                ]
            ], 'User created successfully', 201);
        } catch (\Exception $e) {
            return $this->error('Failed to create user: ' . $e->getMessage(), 500);
        }
    }
    /**
     * @OA\Post(
     *     path="/api/forgot-password",
     *     summary="Send password reset link",
     *     description="Sends a password reset link to the user's registered email address. The user will receive an email with a secure link to reset their password.",
     *     operationId="forgotPassword",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         description="Email address to send password reset link to",
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(
     *                 property="email",
     *                 type="string",
     *                 format="email",
     *                 example="john.doe@example.com",
     *                 description="User's registered email address"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Password reset link sent successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Password reset link sent to your email"),
     *             @OA\Property(property="data", type="null", example=null)
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="User not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="User not found")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Validation failed"),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 example={
     *                     "email": {
     *                         "The email field is required.",
     *                         "The email must be a valid email address.",
     *                         "The selected email is invalid."
     *                     }
     *                 }
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Internal server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Failed to send password reset email")
     *         )
     *     )
     * )
     */
    public function forgotPassword(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|exists:users,email',
        ]);

        if ($validator->fails()) {
            return $this->validationError($validator->errors());
        }

        $user = User::where('email', $request->email)->first();
        if (!$user) {
            return $this->error('User not found', 404);
        }

        // Generate a password reset token
        $token = app('auth.password.broker')->createToken($user);

        // Send the reset link via email
        $user->sendPasswordResetNotification($token);

        return $this->success(null, 'Password reset link sent to your email');
    }

    /**
     * Get current authenticated user profile.
     */
    /**
     * @OA\Get(
     *     path="/api/profile",
     *     summary="Retrieve current authenticated user profile",
     *     description="Returns the profile details of the currently logged in user including roles and permissions.",
     *     operationId="getProfile",
     *     tags={"Profile"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Profile retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Profile retrieved successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="first_name", type="string", example="John"),
     *                 @OA\Property(property="last_name", type="string", example="Doe"),
     *                 @OA\Property(property="email", type="string", example="john.doe@example.com"),
     *                 @OA\Property(property="phone_number", type="string", example="+1234567890"),
     *                 @OA\Property(property="roles", type="array",
     *                     @OA\Items(type="string", example="admin")
     *                 ),
     *                 @OA\Property(property="permissions", type="array",
     *                     @OA\Items(type="string", example="edit-users")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized - Invalid or missing token",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     )
     * )
     */
    public function profile(): JsonResponse
    {
        $user = User::with('roles', 'permissions')->find(Auth::id());

        return $this->success($user, 'Profile retrieved successfully');
    }

    /**
     * Update current authenticated user profile.
     */
    /**
     * @OA\Put(
     *     path="/api/profile",
     *     summary="Update current user profile",
     *     description="Update the profile information of the currently authenticated user. Users can update their personal details and optionally change their password by providing the current password.",
     *     operationId="updateProfile",
     *     tags={"Profile"},
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=false,
     *         description="Profile update data - all fields are optional",
     *         @OA\JsonContent(
     *             @OA\Property(property="first_name", type="string", maxLength=255, example="John", description="User's first name"),
     *             @OA\Property(property="last_name", type="string", maxLength=255, example="Doe", description="User's last name"),
     *             @OA\Property(property="email", type="string", format="email", example="john.doe@example.com", description="User's email address (must be unique)"),
     *             @OA\Property(property="phone_number", type="string", example="+1234567890", description="User's phone number (must be unique)"),
     *             @OA\Property(property="password", type="string", format="password", minLength=8, example="newpassword123", description="New password (optional)"),
     *             @OA\Property(property="current_password", type="string", format="password", example="currentpassword123", description="Current password (required when changing password)")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Profile updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Profile updated successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/User")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Bad Request - Current password is incorrect",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Current password is incorrect")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized - Invalid or missing token",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Validation failed"),
     *             @OA\Property(property="errors", type="object", 
     *                 example={
     *                     "email": {"The email has already been taken."},
     *                     "phone_number": {"The phone number has already been taken."},
     *                     "current_password": {"The current password field is required when password is present."}
     *                 }
     *             )
     *         )
     *     )
     * )
     */
    public function updateProfile(Request $request): JsonResponse
    {
        $user = Auth::user();
        /** @var \App\Models\User $user */

        $validator = Validator::make($request->all(), [
            'first_name' => 'string|max:255',
            'last_name' => 'string|max:255',
            'email' => ['email', Rule::unique('users')->ignore($user->id)],
            'phone_number' => ['string', Rule::unique('users')->ignore($user->id)],
            'current_password' => 'required_with:password|string'
        ]);

        if ($validator->fails()) {
            return $this->validationError($validator->errors());
        }

        // Verify current password if changing password
        if ($request->has('password')) {
            if (!Hash::check($request->current_password, $user->password)) {
                return $this->error('Current password is incorrect', 400);
            }
        }

        $updateData = $request->only(['first_name', 'last_name', 'email', 'phone_number']);

        $user->update($updateData);
        $user->load('roles');

        return $this->success($user, 'Profile updated successfully');
    }

    /**
     * User login.
     */
    /**
     * @OA\Post(
     *     path="/api/login",
     *     summary="User login",
     *     description="Authenticate a user with email and password, returns JWT token and user information",
     *     operationId="login",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         description="User login credentials",
     *         @OA\JsonContent(
     *             required={"email", "password"},
     *             @OA\Property(
     *                 property="email",
     *                 type="string",
     *                 format="email",
     *                 example="john.doe@example.com",
     *                 description="User's email address"
     *             ),
     *             @OA\Property(
     *                 property="password",
     *                 type="string",
     *                 format="password",
     *                 example="password123",
     *                 description="User's password"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Login successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Logged in successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(
     *                     property="token",
     *                     type="string",
     *                     example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwMDAvYXBpL2xvZ2luIiwiaWF0IjoxNjMwNTQ0ODAwLCJleHAiOjE2MzA1NDg0MDAsIm5iZiI6MTYzMDU0NDgwMCwianRpIjoiSGxaQWVZd3ByUVg1a0N6cCIsInN1YiI6MSwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.Tx8z0qK3OOq5Db8I9hPNNX5Y7r3_vP5vKBIZt5_M1wU",
     *                     description="JWT authentication token"
     *                 ),
     *                 @OA\Property(
     *                     property="user",
     *                     ref="#/components/schemas/User",
     *                     description="Authenticated user information"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid credentials",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Invalid credentials")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Validation failed"),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 example={
     *                     "email": {"The email field is required.", "The email must be a valid email address."},
     *                     "password": {"The password field is required."}
     *                 }
     *             )
     *         )
     *     )
     * )
     */
    public function login(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email'    => 'required|email',
            'password' => 'required|string'
        ]);

        if ($validator->fails()) {
            return $this->validationError($validator->errors());
        }

        if (!$token = Auth::attempt($request->only('email', 'password'))) {
            return $this->error('Invalid credentials', 401);
        }

        $user = Auth::user();

        return $this->success([
            'token' => $token,
            'user'  => $user
        ], 'Logged in successfully');
    }

    /**
     * User logout.
     */
    /**
     * User Logout
     * 
     * Logs out the currently authenticated user by invalidating their session/token.
     * This endpoint terminates the user's active session and requires authentication.
     * 
     * @OA\Post(
     *     path="/logout",
     *     tags={"Authentication"},
     *     summary="Logout user",
     *     description="Logs out the currently authenticated user and invalidates their session",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Successfully logged out",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully logged out")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized - Invalid or missing authentication token",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="Unauthorized")
     *         )
     *     )
     * )
     */
    public function logout(Request $request): JsonResponse
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return $this->error('Failed to logout, please try again.', 500);
        }

        return $this->success(null, 'Logged out successfully');
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
            $user = User::findOrFail($id);

            if (!hash_equals((string) $hash, sha1($user->getEmailForVerification()))) {
                return $this->error('Invalid verification link', 400);
            }

            if (!URL::hasValidSignature($request)) {
                return $this->error('Invalid or expired verification link', 400);
            }

            if ($user->hasVerifiedEmail()) {
                return $this->error('Email already verified', 400);
            }

            if ($user->markEmailAsVerified()) {
                event(new Verified($user));
                return $this->success(null, 'Email verified successfully');
            }

            return $this->error('Failed to verify email', 500);
        } catch (\Exception $e) {
            return $this->error('User not found', 404);
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
        $user = $request->user();

        if ($user->hasVerifiedEmail()) {
            return $this->error('Email already verified', 400);
        }

        try {
            $user->sendEmailVerificationNotification();
            return $this->success(null, 'Verification email sent successfully');
        } catch (\Exception $e) {
            return $this->error('Failed to send verification email', 500);
        }
    }

    /**
     * Generate a random OTP.
     */
    private function generateOTP(): string
    {
        return str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Return success response.
     */
    private function success($data = null, string $message = 'Success', int $status = 200): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => $message,
            'data' => $data
        ], $status);
    }

    /**
     * Return error response.
     */
    private function error(string $message, int $status = 500): JsonResponse
    {
        return response()->json([
            'success' => false,
            'message' => $message
        ], $status);
    }

    /**
     * Return forbidden response.
     */
    private function forbidden(string $message = 'Forbidden'): JsonResponse
    {
        return response()->json([
            'success' => false,
            'message' => $message
        ], 403);
    }

    /**
     * Return validation error response.
     */
    private function validationError($errors): JsonResponse
    {
        return response()->json([
            'success' => false,
            'message' => 'Validation failed',
            'errors' => $errors
        ], 422);
    }
}
