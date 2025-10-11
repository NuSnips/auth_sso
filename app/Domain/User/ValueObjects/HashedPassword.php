<?php

namespace App\Domain\User\ValueObjects;

use Illuminate\Support\Facades\Hash;
use InvalidArgumentException;


class HashedPassword
{

    private string $hashed;
    public function __construct(string $hashedString)
    {
        if (strlen($hashedString) === 0) {
            throw new InvalidArgumentException("Hashed password cannot be empty.");
        }
        if (!Hash::isHashed($hashedString)) {
            throw new InvalidArgumentException("Invalid hash value.");
        }
        $this->hashed = $hashedString;
    }

    public static function fromPlainText(string $plainText): self
    {
        if (strlen(trim($plainText)) < 8) {
            throw new InvalidArgumentException("Password must be at 8 characters.");
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
