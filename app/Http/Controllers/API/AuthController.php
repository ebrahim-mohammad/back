<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreUserRequest;
use App\Http\Resources\UserResource;
use App\Http\Traits\ApiResponseTrait;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    use ApiResponseTrait;

    public function register(StoreUserRequest $request){
        $user = $request->validated();

        $user = User::create([
            'name' => $user['name'],
            'email' => $user['email'],
            'password' => Hash::make($user['password']),
        ]);

        $token = $user->createToken('authToken')->plainTextToken;

        return $this->apiResponse(new UserResource($user), $token, 'registered successfully', 200);

    }

    public function login(Request $request){
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                'message' => 'Invalid login details'
            ], 401);
        }

        $user = User::where('email', $request['email'])->firstOrFail();

        $token = $user->createToken('authToken')->plainTextToken;

        return response()->json([
                'access_token' => $token,
                'token_type' => 'Bearer',
        ]);
    }
}
