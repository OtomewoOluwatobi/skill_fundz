<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Proposal;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class ProposalController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api');
    }

    // Helper method to check if user is admin
    private function isAdmin(User $user): bool
    {
        return $user->hasRole('admin');
    }

    // Helper method to check if user is entrepreneur
    private function isEntrepreneur(User $user): bool
    {
        return $user->hasRole('entrepreneur');
    }

    // Helper method to check if user is sponsor
    private function isSponsor(User $user): bool
    {
        return $user->hasRole('sponsor');
    }

    /**
     * @OA\Get(
     *     path="/api/proposals",
     *     summary="Get paginated proposals",
     *     description="Retrieve proposals based on user role - entrepreneurs see their own, sponsors see approved ones, admins see all",
     *     operationId="getProposals",
     *     tags={"Proposals"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="status",
     *         in="query",
     *         description="Filter by proposal status",
     *         required=false,
     *         @OA\Schema(type="string", enum={"submitted", "approved", "sponsored", "declined"})
     *     ),
     *     @OA\Parameter(
     *         name="per_page",
     *         in="query",
     *         description="Number of items per page",
     *         required=false,
     *         @OA\Schema(type="integer", default=15)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Proposals retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="data", type="object"),
     *             @OA\Property(property="message", type="string", example="Proposals retrieved successfully")
     *         )
     *     )
     * )
     */
    public function index(Request $request): JsonResponse
    {
        $user = Auth::user();
        $query = Proposal::with(['user']);

        // Role-based filtering
        if ($this->isEntrepreneur($user)) {
            $query->where('user_id', $user->id);
        } elseif ($this->isSponsor($user)) {
            $query->whereIn('status', [Proposal::PROPOSAL_STATUSES['APPROVED'], Proposal::PROPOSAL_STATUSES['SPONSORED']]);
        }
        // Admins see all proposals

        // Status filtering
        if ($request->filled('status')) {
            $query->where('status', $request->status);
        }

        $proposals = $query->paginate($request->get('per_page', 15));

        return $this->success($proposals, 'Proposals retrieved successfully');
    }

    /**
     * @OA\Post(
     *     path="/api/proposals",
     *     summary="Create new proposal (entrepreneurs only)",
     *     description="Create a new funding proposal (entrepreneurs only)",
     *     operationId="createProposal",
     *     tags={"Proposals"},
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"title", "description", "funding_goal", "timeline"},
     *                 @OA\Property(property="title", type="string", example="Innovative Tech Startup"),
     *                 @OA\Property(property="description", type="string", example="Revolutionary app that solves real-world problems"),
     *                 @OA\Property(property="funding_goal", type="number", format="float", example=50000.00),
     *                 @OA\Property(property="timeline", type="string", example="6 months"),
     *                 @OA\Property(property="expected_impact", type="string", example="Will benefit 10,000+ users"),
     *                 @OA\Property(property="video_pitch", type="string", format="binary", description="Optional video file"),
     *                 @OA\Property(property="documents", type="array", @OA\Items(type="string", format="binary"), description="Supporting documents")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Proposal created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="data", type="object"),
     *             @OA\Property(property="message", type="string", example="Proposal created successfully")
     *         )
     *     )
     * )
     */
    public function store(Request $request): JsonResponse
    {
        // Check if user is entrepreneur
        if (!$this->isEntrepreneur(Auth::user())) {
            return $this->error('Only entrepreneurs can create proposals', 403);
        }

        $validator = Validator::make($request->all(), [
            'title' => 'required|string|max:255',
            'description' => 'required|string|min:100',
            'funding_goal' => 'required|numeric|min:1000',
            'timeline' => 'required|string|max:100',
            'expected_impact' => 'nullable|string',
            'video_pitch' => 'nullable|file|mimes:mp4,avi,mov|max:51200', // 50MB max
            'documents.*' => 'nullable|file|mimes:pdf,doc,docx|max:10240', // 10MB max per file
        ]);

        if ($validator->fails()) {
            return $this->error('Validation failed', 422, $validator->errors());
        }

        $proposalData = $request->only(['title', 'description', 'funding_goal', 'timeline', 'expected_impact']);
        $proposalData['user_id'] = Auth::id();
        $proposalData['status'] = Proposal::PROPOSAL_STATUSES['SUBMITTED'];

        // Handle file uploads
        if ($request->hasFile('video_pitch')) {
            $proposalData['video_pitch'] = $request->file('video_pitch')->store('proposals/videos', 'public');
        }

        if ($request->hasFile('documents')) {
            $documents = [];
            foreach ($request->file('documents') as $document) {
                $documents[] = $document->store('proposals/documents', 'public');
            }
            $proposalData['documents'] = json_encode($documents);
        }

        $proposal = Proposal::create($proposalData);
        $proposal->load(['user']);

        return $this->success($proposal, 'Proposal created successfully', 201);
    }

    /**
     * @OA\Get(
     *     path="/api/proposals/{id}",
     *     summary="Get proposal details",
     *     description="Retrieve detailed information about a specific proposal",
     *     operationId="getProposal",
     *     tags={"Proposals"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Proposal retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="data", type="object"),
     *             @OA\Property(property="message", type="string", example="Proposal retrieved successfully")
     *         )
     *     )
     * )
     */
    public function show(string $id): JsonResponse
    {
        $proposal = Proposal::with(['user'])->find($id);

        if (!$proposal) {
            return $this->error('Proposal not found', 404);
        }

        // Check access permissions
        $user = Auth::user();
        if ($this->isEntrepreneur($user) && $proposal->user_id !== $user->id) {
            return $this->error('Unauthorized to view this proposal', 403);
        }

        if ($this->isSponsor($user) && !in_array($proposal->status, [
            Proposal::PROPOSAL_STATUSES['APPROVED'],
            Proposal::PROPOSAL_STATUSES['SPONSORED']
        ])) {
            return $this->error('Proposal not available for sponsorship', 403);
        }

        return $this->success($proposal, 'Proposal retrieved successfully');
    }

    /**
     * @OA\Put(
     *     path="/api/proposals/{id}",
     *     summary="Update proposal (entrepreneurs for their own, admins for any)",
     *     description="Update proposal details (entrepreneurs for their own, admins for any)",
     *     operationId="updateProposal",
     *     tags={"Proposals"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="title", type="string"),
     *             @OA\Property(property="description", type="string"),
     *             @OA\Property(property="funding_goal", type="number"),
     *             @OA\Property(property="timeline", type="string"),
     *             @OA\Property(property="expected_impact", type="string")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Proposal updated successfully"
     *     )
     * )
     */
    public function update(Request $request, string $id): JsonResponse
    {
        $proposal = Proposal::find($id);

        if (!$proposal) {
            return $this->error('Proposal not found', 404);
        }

        $user = Auth::user();
        
        // Check permissions
        if (!$this->isAdmin($user) && 
            (!$this->isEntrepreneur($user) || $proposal->user_id !== $user->id)) {
            return $this->error('Unauthorized to update this proposal', 403);
        }

        // Prevent updates for sponsored proposals
        if (in_array($proposal->status, [Proposal::PROPOSAL_STATUSES['SPONSORED']])) {
            return $this->error('Cannot update sponsored proposals', 400);
        }

        $validator = Validator::make($request->all(), [
            'title' => 'sometimes|string|max:255',
            'description' => 'sometimes|string|min:100',
            'funding_goal' => 'sometimes|numeric|min:1000',
            'timeline' => 'sometimes|string|max:100',
            'expected_impact' => 'sometimes|string',
        ]);

        if ($validator->fails()) {
            return $this->error('Validation failed', 422, $validator->errors());
        }

        $proposal->update($request->only(['title', 'description', 'funding_goal', 'timeline', 'expected_impact']));
        $proposal->load(['user']);

        return $this->success($proposal, 'Proposal updated successfully');
    }

    /**
     * @OA\Patch(
     *     path="/api/proposals/{id}/status",
     *     summary="Update proposal status (admin only)",
     *     description="Update proposal status (admin only)",
     *     operationId="updateProposalStatus",
     *     tags={"Proposals"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"status"},
     *             @OA\Property(property="status", type="string", enum={"submitted", "approved", "sponsored", "declined"}),
     *             @OA\Property(property="admin_notes", type="string", description="Optional admin notes")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Proposal status updated successfully"
     *     )
     * )
     */
    public function updateStatus(Request $request, string $id): JsonResponse
    {
        if (!$this->isAdmin(Auth::user())) {
            return $this->error('Only admins can update proposal status', 403);
        }

        $proposal = Proposal::find($id);

        if (!$proposal) {
            return $this->error('Proposal not found', 404);
        }

        $validator = Validator::make($request->all(), [
            'status' => 'required|in:' . implode(',', Proposal::PROPOSAL_STATUSES),
            'admin_notes' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return $this->error('Validation failed', 422, $validator->errors());
        }

        $proposal->update([
            'status' => $request->status,
            'admin_notes' => $request->admin_notes,
            'reviewed_at' => now(),
            'reviewed_by' => Auth::id(),
        ]);

        return $this->success($proposal, 'Proposal status updated successfully');
    }

    /**
     * @OA\Delete(
     *     path="/api/proposals/{id}",
     *     summary="Delete proposal (entrepreneurs for their own, admins for any)",
     *     description="Soft delete a proposal (entrepreneurs for their own, admins for any)",
     *     operationId="deleteProposal",
     *     tags={"Proposals"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Proposal deleted successfully"
     *     )
     * )
     */
    public function destroy(string $id): JsonResponse
    {
        $proposal = Proposal::find($id);

        if (!$proposal) {
            return $this->error('Proposal not found', 404);
        }

        $user = Auth::user();
        
        // Check permissions
        if (!$this->isAdmin($user) && 
            (!$this->isEntrepreneur($user) || $proposal->user_id !== $user->id)) {
            return $this->error('Unauthorized to delete this proposal', 403);
        }

        // Prevent deletion of sponsored proposals
        if ($proposal->status === Proposal::PROPOSAL_STATUSES['SPONSORED']) {
            return $this->error('Cannot delete sponsored proposals', 400);
        }

        $proposal->delete();

        return $this->success(null, 'Proposal deleted successfully');
    }

    /**
     * @OA\Get(
     *     path="/api/proposals/statuses",
     *     summary="Get available proposal statuses",
     *     description="Retrieve list of all available proposal statuses",
     *     operationId="getProposalStatuses",
     *     tags={"Proposals"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Statuses retrieved successfully"
     *     )
     * )
     */
    public function getStatuses(): JsonResponse
    {
        return $this->success(Proposal::listProposalStatuses(), 'Statuses retrieved successfully');
    }

    private function success($data = null, string $message = 'Success', int $status = 200): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => $message,
            'data' => $data
        ], $status);
    }

    private function error(string $message, int $status = 500, $errors = null): JsonResponse
    {
        $response = [
            'success' => false,
            'message' => $message
        ];

        if ($errors) {
            $response['errors'] = $errors;
        }

        return response()->json($response, $status);
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
