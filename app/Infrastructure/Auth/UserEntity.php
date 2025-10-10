<?php

namespace App\Infrastructure\Auth;

use Illuminate\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class UserEntity extends Authenticatable
{

    use HasApiTokens, HasFactory, Notifiable, MustVerifyEmail;
    protected $table = "users";

    protected $fillable = ['first_name', 'last_name', 'email', 'password', 'is_active'];

    protected $hidden = ['password'];
    protected $casts = ['email_verified_at' => 'datetime', 'password' => 'hashed'];
}
