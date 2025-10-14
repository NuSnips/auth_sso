<?php

use App\Domain\User\ValueObjects\Email;

describe("Email Value Object", function () {
    // can create a valid email
    it('creates a valid Email', function () {
        $email = new Email("jane@email.com");
        expect($email)->toBeInstanceOf(Email::class)
            ->and($email->value())->toBe('jane@email.com');
    });

    it('creates a valid Email using fromString', function () {
        $email = Email::fromString("jane@email.com");
        expect($email)->toBeInstanceOf(Email::class)
            ->and($email->value())->toBe('jane@email.com');
    });
    // throws an exception for invalid emails
    it('throws exception for invalid email format', function ($invalid) {
        expect(fn() => new Email($invalid))->toThrow(InvalidArgumentException::class, "Invalid email format: {$invalid}");
    })->with([
        'invalid-email',
        'jane@smith@email.com',
        '@email.com',
        'jane@emailcom'
    ]);

    // can compare email address
    it('compares two emails', function () {
        $email = new Email("jane@email.com");
        expect($email->value())->toEqual("jane@email.com");
    });
    // returns a string value of email
    it('returns a string value of the email with value()', function () {
        $email = Email::fromString("jack@email.com");
        expect($email->value())->toBeString()->toEqual("jack@email.com");
    });

    it('returns a string value of the email with __toString', function () {
        $email = Email::fromString("jack@email.com");
        expect($email->__toString())->toBeString()->toEqual("jack@email.com");
    });
});
