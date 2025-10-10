<?php

namespace App\Domain\User\Models;

use App\Domain\User\ValueObjects\FullName;
use Illuminate\Database\Eloquent\Model;

class User extends Model
{

    protected $fillable = ['first_name', 'last_name', 'email', 'password', 'is_active'];

    protected $hidden = [
        'password',

    ];
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    public function rename(FullName $fullName)
    {
        $this->first_name = $fullName->first();
        $this->last_name = $fullName->last();
    }

    public function getFullName(): string
    {
        return "{$this->first_name} {$this->last_name}";
    }
}
