<?php

namespace App\Domain\User\ValueObjects;

class FullName
{
    public function __construct(private string $first, private string $last) {}

    public static function fromString(string $first, string $last): FullName
    {
        if ($first === $last) {
            throw new \InvalidArgumentException("First and Last name cannot be the same.");
        }
        if ($first === "" || $last === "") {
            throw new \InvalidArgumentException("First and Last name cannot be empty.");
        }
        return new FullName($first, $last);
    }

    public function first(): string
    {
        return $this->first;
    }

    public function last(): string
    {
        return $this->last;
    }

    public function value(): string
    {
        return "{$this->first()} {$this->last}";
    }
}
