<?php

namespace App\Domain\User\ValueObjects;

use InvalidArgumentException;

class Email
{
    private $email;
    public function __construct(string $email)
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new InvalidArgumentException("Invalid email format: {$email}");
        }
        $this->email = $email;
    }
    public function value(): string
    {
        return $this->email;
    }

    public function equals(Email $email): bool
    {
        return $this->email === $email->email;
    }

    public function __toString(): string
    {
        return $this->email;
    }
}
