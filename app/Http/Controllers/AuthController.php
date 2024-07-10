<?php

namespace App\Http\Controllers;
// namespace App\Http\Resources\userResource;

use App\Http\Resources\UserCollection;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

use function Pest\Laravel\json;

class AuthController extends Controller
{
    public function register(Request $request) {
        $data = $request->validate([
            'name'=> ['required', 'string'],
            'email'=> ['required', 'email', 'unique:users'],
            'password'=> ['required', 'min:6'],
        ]);

        $user = User::create($data);
        $token = $user->createToken('auth_token')->plainTextToken;
        return [
            'user'=> $user,
            'token'=> $token,
        ];
    }

    public function login(Request $request) {
        $data = $request->validate([
            'email'=> ['required', 'email', 'exists:users'],
            'password'=> ['required', 'min:6'],
        ]);

        $user = User::where('email', $data['email'])->first();
        if (!$user || !Hash::check($data['password'], $user->password)) {
            return response([
                'message' => 'Not correct'
            ], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;
        return [
            'user'=> $user,
            'token'=> $token,
        ];
    }

    public function userprofile() {
        $userdata = auth()->user();
        return response()->json([
            'status' => true,
            'message' => 'User Login Profile',
            'data' => $userdata,
            'id' => auth()->user()->id
        ], 200);
    }

    public function userResource() {
        $userdata = new UserResource(User::findOrfail(auth()->user()->id));
        return response()->json([
            'status' => true,
            'message' => 'User Login Profile using API resource',
            'data' => $userdata,
            'id' => auth()->user()->id
        ], 200);
    }

    public function userResourceCollection() {
        $userdata = UserResource::collection(User::all());
        return response()->json([
            'status' => true,
            'message' => 'User Login Profile using API resource as collection',
            'data' => $userdata,
            'id' => auth()->user()->id
        ], 200);
    }

    public function userCollection() {
        $userdata = new UserCollection(User::all());
        return response()->json([
            'status' => true,
            'message' => 'User Login Profile using API ResourceCollection',
            'data' => $userdata,
            'id' => auth()->user()->id
        ], 200);
    }

    public function logout() {
        auth()->user()->tokens()->delete();
        return response()->json([
            'status' => true,
            'message'=> 'Logout Token',
            'data' => []
        ], 200);
    }
}
