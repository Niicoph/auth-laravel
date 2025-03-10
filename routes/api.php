<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;



Route::post('/auth/login', [AuthController::class, 'login']);
Route::middleware('auth.jwt')->get('/auth/refresh', [AuthController::class, 'refresh']);
