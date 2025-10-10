<?php

namespace App\Domain\User\ValueObjects;

use Illuminate\Support\Facades\Hash;

class HashedPassword
{

    public function __construct(private string $hashed) {}

    public static function fromPlainText(string $plainText): self
    {
        if (strlen($plainText) < 8) {
            throw new \InvalidArgumentException("Password must be at 8 characters.");
        }
        return new self(Hash::make($plainText));
    }

    public static function fromHash(string $hashed): self
    {
        return new self($hashed);
    }

    public function verify(string $value): bool
    {
        return Hash::check($value, $this->hashed);
    }

    public function __toString(): string
    {
        return $this->hashed;
    }
}
