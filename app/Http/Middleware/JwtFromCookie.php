<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Response;

class JwtFromCookie
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return \Illuminate\Http\Response
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            $token = $request->cookie('sessionID');
            if (!$token) {
                $refreshToken = $request->cookie('refreshToken');
                if (!$refreshToken) {
                    return response()->json(['message' => 'No token or refresh token provided'], 401);
                }
                $newToken = JWTAuth::refresh($refreshToken);
                return $next($request)->cookie('sessionID', $newToken, 60, '/', null, true, true);
            }
            if (!JWTAuth::setToken($token)->check()) {
                $refreshToken = $request->cookie('refreshToken');

                if (!$refreshToken || !JWTAuth::setToken($refreshToken)->check()) {
                    return response()->json(['message' => 'Unauthenticated. Please login again.'], 401);
                }
                $newToken = JWTAuth::refresh($refreshToken);
                return $next($request)->cookie('sessionID', $newToken, 60, '/', null, true, true);
            }
            return $next($request);
        } catch (JWTException $e) {
            return response()->json(['message' => 'Could not authenticate token.'], 500);
        }
    }
}
