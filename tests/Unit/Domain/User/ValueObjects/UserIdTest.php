<?php

use App\Domain\User\ValueObjects\UserId;
use Ramsey\Uuid\Uuid;

describe('UserId Value Object', function () {

    it('can create a user ID from a valid UUID string', function () {
        $uuid = Uuid::uuid4()->toString();
        $userID = new UserId($uuid);
        expect($userID->__toString())->toBe($uuid);
    });

    it('throws an exception when created with an invalid UUID', function ($invalid) {
        new UserId($invalid);
    })->throws(InvalidArgumentException::class, 'User ID must be a string.')
        ->with([
            'blank string' => '',
            'number' => 123,
            'string with spaces' => 'invalid uuid',
            'string with dashes' => 'this-seems-like-valid-but-do-we-think-it-is',
            'alphanumeric string with dashes' => 'dhgjfkrd-fghy-drgh-ff3d-kghj4hfjd8j3'
        ]);

    it('generates a valid user ID', function () {
        $userId = UserId::generate();

        expect($userId)->toBeInstanceOf(UserId::class)
            ->and(Uuid::isValid($userId->__toString()))->toBeTrue();
    });

    it('can create a user ID from a valid UUID string using fromString', function () {
        $uuidString = Uuid::uuid4()->toString();
        $userId = UserId::fromString($uuidString);
        expect($userId)->toBeInstanceOf(UserId::class)
            ->and($userId->__toString())->toEqual($uuidString);
    });

    it('returns true when comparing similar user IDs.', function () {
        $uuid = Uuid::uuid4()->toString();
        $userId = UserId::fromString($uuid);
        expect($userId->equals($uuid))->toBeTrue();
    });

    it('returns false when comparing different user IDs.', function () {
        $uuid = Uuid::uuid4()->toString();
        $userId = new UserId(Uuid::uuid4()->toString());
        expect($userId->equals($uuid))->toBeFalse();
    });
    it('returns the user ID', function () {
        $uuid = Uuid::uuid4()->toString();
        $userId = UserId::fromString($uuid);
        expect($userId->value())->toBe($uuid);
    });

    it('converts to string correctly', function () {
        $uuid = Uuid::uuid4()->toString();
        $userId = UserId::fromString($uuid);
        expect((string)$userId)->toBe($uuid)
            ->and($userId->__toString())->toBe($uuid);
    });

    it('generates unique user IDs.', function () {
        $userId1 = UserId::generate();
        $userId2 = UserId::generate();
        expect($userId1)->not->toBe($userId2);
    });

    it('accepts various valid UUID formats', function ($uuid) {
        $userId = UserId::fromString($uuid);
        expect($userId->__toString())->toBe($uuid);
    })->with([
        'lowercase UUDI' => strtolower(Uuid::uuid4()->toString()),
        'uppercase UUID' => strtoupper(Uuid::uuid4()->toString())
    ]);
});
