<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException as ExceptionsJWTException;
use Illuminate\Support\Str;
use App\Models\User;

class AuthController extends Controller
{
    public function __construct()
    {
        // $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**
     * Login a user
     * @param LoginRequest $loginRequest
     * @return \Illuminate\Http\JsonResponse // cookies with sessionID and refreshToken
     * @throws ExceptionsJWTException
     */
    public function login(LoginRequest $loginRequest)
    {
        $credentials = $loginRequest->only(['email', 'password']);

        try {
            $token = Auth::attempt($credentials);
            if (!$token) {
                return response()->json(['message' => 'Unauthorized'], 401);
            }

            $user = Auth::user();
            $refreshToken = Str::random(60);
            $userAuth = User::find($user->id);
            $userAuth->remember_token = $refreshToken;
            $userAuth->save();

            return response()->json(['message' => 'Login successful', 'user' => $user])
                ->cookie('sessionID', $token, 60, '/', null, true, true)
                ->cookie('refreshToken', $refreshToken, 20160, '/', null, true, true);
        } catch (ExceptionsJWTException $e) {
            return response()->json(['message' => 'Could not create token'], 500);
        }
    }

    /**
     * Refresh access token using refreshToken
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse // cookies with new sessionID and refreshToken
     * @throws ExceptionsJWTException
     */
    public function refresh(Request $request)
    {
        try {
            $refreshToken = $request->cookie('refreshToken');
            if (!$refreshToken) {
                return response()->json(['message' => 'No refresh token provided'], 401);
            }
            $user = User::where('remember_token', $refreshToken)->first();

            if (!$user) {
                return response()->json(['message' => 'Invalid refresh token'], 401);
            }
            $newToken = Auth::login($user);
            return response()->json(['message' => 'Token refreshed'])->cookie('sessionID', $newToken, 60, '/', null, true, true);
        } catch (ExceptionsJWTException $e) {
            return response()->json(['message' => 'Could not refresh token'], 500);
        }
    }
}
