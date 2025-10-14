<?php

use App\Domain\User\ValueObjects\HashedPassword;
use Illuminate\Support\Facades\Hash;

describe('HashedPassword Value Object', function () {
    it('creates a HashedPassword from a string', function () {
        $hashed = Hash::make("Password@123");
        $hashedPassword = new HashedPassword($hashed);
        expect($hashedPassword)->toBeInstanceOf(HashedPassword::class);
    });

    it('throws an exception when created with an empty string', function () {
        new HashedPassword('');
    })->throws(InvalidArgumentException::class, 'Hashed password cannot be empty.');

    it('throws an exception when created with a non-hashed value', function () {
        new HashedPassword("Not@HashedValue123");
    })->throws(InvalidArgumentException::class, 'Invalid hash value.');

    it('creates a HashedPassword when given a string', function () {
        $string = "Password@123";
        $hashedPassword = HashedPassword::fromPlainText($string);
        expect($hashedPassword)->toBeInstanceOf(HashedPassword::class)
            ->and(Hash::isHashed($hashedPassword->__toString()))->toBeTrue();
    });

    it('throws an exception when given a string that has less than 8 characters', function ($invalid) {
        HashedPassword::fromPlainText($invalid);
    })->throws(InvalidArgumentException::class, 'Password must be at 8 characters.')
        ->with([
            'less than 8 characters' => 'Not@8',
            'trailing spaces' => 'Not@8    ',
            'leading spaces' => '    Not@8'
        ]);

    it('creates a HashedPassword from a hashed string using fromHash', function () {
        $hashed = Hash::make("Password@1234");
        $hashedPassword = HashedPassword::fromHash($hashed);
        expect($hashedPassword)->toBeInstanceOf(HashedPassword::class);
    });

    it('can verify a string against its hashed value', function () {
        $string = "Password@1234";
        $hashedPassword = HashedPassword::fromPlainText($string);
        expect($hashedPassword->verify($string))->toBeTrue();
        expect($hashedPassword->verify("SomeOther@12345"))->toBeFalse();
    });

    it('converts a string to string correctly', function () {
        $hashed = Hash::make("Password@1234");
        $hashedPassword = new HashedPassword($hashed);
        expect($hashedPassword->__toString())->toBe($hashed);
    });
});
