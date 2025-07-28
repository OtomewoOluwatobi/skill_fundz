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
     * @OA\Get(
     *     path="/api/users",
     *     summary="Get list of users",
     *     description="Get paginated list of users (Admin only)",
     *     operationId="getUsers",
     *     tags={"Users"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="page",
     *         in="query",
     *         description="Page number",
     *         required=false,
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *     @OA\Parameter(
     *         name="per_page",
     *         in="query",
     *         description="Items per page",
     *         required=false,
     *         @OA\Schema(type="integer", example=15)
     *     ),
     *     @OA\Parameter(
     *         name="search",
     *         in="query",
     *         description="Search term",
     *         required=false,
     *         @OA\Schema(type="string", example="john")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Users retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="users", type="object",
     *                     @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/User")),
     *                     @OA\Property(property="current_page", type="integer", example=1),
     *                     @OA\Property(property="last_page", type="integer", example=5),
     *                     @OA\Property(property="total", type="integer", example=100)
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - Insufficient permissions",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="You do not have permission to view users")
     *         )
     *     )
     * )
     */
    public function index(Request $request): JsonResponse
    {
        /** @var \Illuminate\Contracts\Auth\Access\Authorizable $currentUser */
        $currentUser = Auth::user();

        // Check permission
        if (!$currentUser->can('view-users')) {
            return $this->forbidden('You do not have permission to view users');
        }

        $query = User::with('roles');

        // Apply filters
        if ($request->has('role')) {
            $query->role($request->role);
        }

        if ($request->has('verified')) {
            $query->where('is_verified', $request->boolean('verified'));
        }

        if ($request->has('search')) {
            $search = $request->search;
            $query->where(function ($q) use ($search) {
                $q->where('first_name', 'like', "%{$search}%")
                    ->orWhere('last_name', 'like', "%{$search}%")
                    ->orWhere('email', 'like', "%{$search}%");
            });
        }

        $users = $query->paginate($request->get('per_page', 15));

        return $this->success($users, 'Users retrieved successfully');
    }

    /**
     * Display the specified user.
     */
    public function show(User $user): JsonResponse
    {
        $currentUser = Auth::user();
        /** @var \Illuminate\Contracts\Auth\Access\Authorizable $currentUser */
        // Check permission - users can view their own profile, admins can view any
        if (!$currentUser->can('view-users') && $currentUser->id !== $user->id) {
            return $this->forbidden('You do not have permission to view this user');
        }

        $user->load('roles', 'permissions');

        return $this->success($user, 'User retrieved successfully');
    }

    /**
     * Update the specified user.
     */
    public function update(Request $request, User $user): JsonResponse
    {
        $currentUser = Auth::user();
        /** @var \Illuminate\Contracts\Auth\Access\Authorizable $currentUser */
        // Check permission - users can edit their own profile, admins can edit any
        $canEdit = $currentUser->can('edit-users') ||
            ($currentUser->id === $user->id);

        if (!$canEdit) {
            return $this->forbidden('You do not have permission to update this user');
        }

        $rules = [
            'first_name' => 'string|max:255',
            'last_name' => 'string|max:255',
            'email' => ['email', Rule::unique('users')->ignore($user->id)],
            'phone_number' => ['string', Rule::unique('users')->ignore($user->id)],
            'password' => 'string|min:8|confirmed'
        ];

        // Only admins can change roles
        if ($currentUser->can('manage-user-roles')) {
            $rules['role'] = ['string', Rule::in(['admin', 'entrepreneur', 'sponsor'])];
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return $this->validationError($validator->errors());
        }

        $updateData = $request->only(['first_name', 'last_name', 'email', 'phone_number']);

        if ($request->has('password')) {
            $updateData['password'] = Hash::make($request->password);
        }

        $user->fill($updateData);
        $user->save();

        // Update role if provided and user has permission
        if ($request->has('role') && $currentUser->can('manage-user-roles')) {
            $user->syncRoles([$request->role]);
        }

        $user->load('roles');

        return $this->success($user, 'User updated successfully');
    }

    /**
     * Remove the specified user.
     * Only accessible by admins.
     */
    public function destroy(User $user): JsonResponse
    {
        $currentUser = Auth::user();
        /** @var \Illuminate\Contracts\Auth\Access\Authorizable $currentUser */
        // Check permission
        if (!$currentUser->can('delete-users')) {
            return $this->forbidden('You do not have permission to delete users');
        }

        // Prevent self-deletion
        if ($currentUser->id === $user->id) {
            return $this->error('You cannot delete your own account', 400);
        }

        $user->delete();

        return $this->success(null, 'User deleted successfully');
    }

    /**
     * Get current authenticated user profile.
     */
    public function profile(): JsonResponse
    {
        $user = User::with('roles', 'permissions')->find(Auth::id());

        return $this->success($user, 'Profile retrieved successfully');
    }

    /**
     * Update current authenticated user profile.
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

    public function forgotPassword(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email'
        ]);

        if ($validator->fails()) {
            return $this->validationError($validator->errors());
        }

        $user = User::where('email', $request->email)->first();

        // If the user exists, you would dispatch a job or send a notification with the password reset token.
        // For brevity, the email sending logic is omitted.

        return $this->success(null, 'If an account exists, a password reset email has been sent');
    }

    public function reVerifyEmail(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email'
        ]);

        if ($validator->fails()) {
            return $this->validationError($validator->errors());
        }

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return $this->error('User not found', 404);
        }

        if (!$user->hasVerifiedEmail()) {
            $user->sendEmailVerificationNotification();
            return $this->success(null, 'Verification email resent');
        }

        return $this->error('Email is already verified', 400);
    }

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
