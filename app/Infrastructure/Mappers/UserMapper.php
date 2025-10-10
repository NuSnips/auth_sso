<?php

namespace App\Infrastructure\Mappers;

use App\Infrastructure\Auth\UserEntity;
use App\Domain\User\Models\User as DomainUser;

class UserMapper
{

    /**
     * Convert user entity to domain user
     * @param \App\Infrastructure\Auth\UserEntity $userEntity
     * @return DomainUser
     */
    public static function toDomain(UserEntity $userEntity): DomainUser
    {
        return new DomainUser([
            'first_name' => $userEntity->first_name,
            'last_name' => $userEntity->last_name,
            'email' => $userEntity->email,
            'password' => $userEntity->password
        ]);
    }

    /**
     * Convert domain user to user entity
     * @param \App\Domain\User\Models\User $domainUser
     * @return UserEntity
     */
    public static function toEntity(DomainUser $domainUser): UserEntity
    {
        $userEntity = new UserEntity();
        $userEntity->first_name = $domainUser->first_name;
        $userEntity->last_name = $domainUser->last_name;
        $userEntity->email = $domainUser->email;
        $userEntity->password = $domainUser->password;
        return $userEntity;
    }
}
