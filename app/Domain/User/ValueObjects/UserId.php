<?php

namespace App\Domain\User\ValueObjects;

use Ramsey\Uuid\Uuid;

class UserId
{

    private $id;

    public function __construct(string $id)
    {
        if (!Uuid::isValid($id)) {
            throw new \InvalidArgumentException("User ID must be a string.");
        }
        $this->id = $id;
    }

    public static function generate(): self
    {
        return new self(Uuid::uuid4()->toString());
    }

    public static function fromString(string $uuid): self
    {
        return new self($uuid);
    }

    public function equals(string $userId): bool
    {
        return $this->id === $userId;
    }

    public function value(): string
    {
        return $this->id;
    }

    public function __toString(): string
    {
        return $this->id;
    }
}
