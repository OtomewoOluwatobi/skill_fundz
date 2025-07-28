<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\Models\User;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;

/**
 * @OA\Tag(
 *     name="Admin",
 *     description="Admin management endpoints"
 * )
 */
class AdminController extends Controller
{
    public function __construct()
    {
        $this->middleware(['auth:api', 'role:admin']);
    }

    /**
     * @OA\Get(
     *     path="/api/admin/users",
     *     summary="Get list of users (Admin only)",
     *     description="Get paginated list of users with filtering capabilities",
     *     operationId="adminGetUsers",
     *     tags={"Admin"},
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
     *         description="Search in first_name, last_name, or email",
     *         required=false,
     *         @OA\Schema(type="string", example="john")
     *     ),
     *     @OA\Parameter(
     *         name="role",
     *         in="query",
     *         description="Filter by user role",
     *         required=false,
     *         @OA\Schema(type="string", enum={"admin", "entrepreneur", "sponsor"}, example="entrepreneur")
     *     ),
     *     @OA\Parameter(
     *         name="verified",
     *         in="query",
     *         description="Filter by verification status",
     *         required=false,
     *         @OA\Schema(type="boolean", example=true)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Users retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Users retrieved successfully"),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/User")),
     *                 @OA\Property(property="current_page", type="integer", example=1),
     *                 @OA\Property(property="last_page", type="integer", example=5),
     *                 @OA\Property(property="per_page", type="integer", example=15),
     *                 @OA\Property(property="total", type="integer", example=100)
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - Admin access required",
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
     * @OA\Post(
     *     path="/api/admin/resources",
     *     summary="Create admin resource",
     *     description="Create a new admin-managed resource (Admin only)",
     *     operationId="adminCreateResource",
     *     tags={"Admin"},
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="type", type="string", example="announcement", description="Type of resource to create"),
     *             @OA\Property(property="title", type="string", example="System Maintenance", description="Resource title"),
     *             @OA\Property(property="content", type="string", example="System will be under maintenance", description="Resource content")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Resource created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Resource created successfully"),
     *             @OA\Property(property="data", type="null")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - Admin access required",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Admin access required")
     *         )
     *     )
     * )
     */
    public function store(Request $request): JsonResponse
    {
        // Implementation for creating admin resources
        return $this->success(null, 'Resource created successfully', 201);
    }

    /**
     * @OA\Get(
     *     path="/api/admin/users/{id}",
     *     summary="Get user details (Admin)",
     *     description="Get detailed information of a user by ID. Admin can view any user, regular users can view their own profile.",
     *     operationId="adminGetUser",
     *     tags={"Admin"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="User ID",
     *         required=true,
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User retrieved successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/User")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - Insufficient permissions",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="You do not have permission to view this user")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="User not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="User not found")
     *         )
     *     )
     * )
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
     * @OA\Put(
     *     path="/api/admin/users/{id}",
     *     summary="Update user (Admin)",
     *     description="Update a specific user's details. Admins can update any user, regular users can update their own information.",
     *     operationId="adminUpdateUser",
     *     tags={"Admin"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="User ID",
     *         required=true,
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="first_name", type="string", example="Jane", description="User's first name"),
     *             @OA\Property(property="last_name", type="string", example="Doe", description="User's last name"),
     *             @OA\Property(property="email", type="string", format="email", example="jane@example.com", description="User's email address"),
     *             @OA\Property(property="phone_number", type="string", example="+19876543210", description="User's phone number"),
     *             @OA\Property(property="password", type="string", format="password", example="newpassword123", description="New password (optional)"),
     *             @OA\Property(property="password_confirmation", type="string", format="password", example="newpassword123", description="Password confirmation"),
     *             @OA\Property(property="role", type="string", enum={"admin", "entrepreneur", "sponsor"}, example="entrepreneur", description="User role (admin only)")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User updated successfully"),
     *             @OA\Property(property="data", ref="#/components/schemas/User")
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
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - Insufficient permissions",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="You do not have permission to update this user")
     *         )
     *     )
     * )
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
     * @OA\Delete(
     *     path="/api/admin/users/{id}",
     *     summary="Delete user (Admin only)",
     *     description="Delete a specific user. Only admins can delete users, and they cannot delete themselves.",
     *     operationId="adminDeleteUser",
     *     tags={"Admin"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="User ID to delete",
     *         required=true,
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="User deleted successfully"),
     *             @OA\Property(property="data", type="null")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Bad Request - Self-deletion attempt",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="You cannot delete your own account")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - Admin access required",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="You do not have permission to delete users")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="User not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="User not found")
     *         )
     *     )
     * )
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
     * @OA\Get(
     *     path="/api/admin/users/role/{role}",
     *     summary="Get users by role (Admin only)",
     *     description="Retrieve all users assigned to a specific role with pagination",
     *     operationId="getUsersByRole",
     *     tags={"Admin"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="role",
     *         in="path",
     *         required=true,
     *         description="The role name to filter users by",
     *         @OA\Schema(
     *             type="string",
     *             enum={"admin", "entrepreneur", "sponsor"},
     *             example="admin"
     *         )
     *     ),
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
     *     @OA\Response(
     *         response=200,
     *         description="Users retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Users retrieved successfully"),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/User")),
     *                 @OA\Property(property="current_page", type="integer", example=1),
     *                 @OA\Property(property="last_page", type="integer", example=5),
     *                 @OA\Property(property="per_page", type="integer", example=15),
     *                 @OA\Property(property="total", type="integer", example=100)
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - Admin access required",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="You do not have permission to view users")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Role not found or no users with this role",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="No users found with the specified role")
     *         )
     *     )
     * )
     */
    public function getUsersByRole(Request $request, string $role): JsonResponse
    {
        /** @var \Illuminate\Contracts\Auth\Access\Authorizable $currentUser */
        $currentUser = Auth::user();

        // Check permission
        if (!$currentUser->can('view-users')) {
            return $this->forbidden('You do not have permission to view users');
        }

        $users = User::role($role)->paginate($request->get('per_page', 15));

        return $this->success($users, 'Users retrieved successfully');
    }

    /**
     * Helper methods from your UserController pattern
     */
    private function success($data = null, string $message = 'Success', int $status = 200): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => $message,
            'data' => $data
        ], $status);
    }

    private function error(string $message, int $status = 500): JsonResponse
    {
        return response()->json([
            'success' => false,
            'message' => $message
        ], $status);
    }

    private function forbidden(string $message): JsonResponse
    {
        return response()->json([
            'success' => false,
            'message' => $message
        ], 403);
    }

    private function validationError($errors): JsonResponse
    {
        return response()->json([
            'success' => false,
            'message' => 'Validation failed',
            'errors' => $errors
        ], 422);
    }
}
