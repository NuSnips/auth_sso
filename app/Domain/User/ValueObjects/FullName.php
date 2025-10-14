<?php

namespace App\Domain\User\ValueObjects;

use InvalidArgumentException;

final readonly class FullName
{
    private string $first;
    private string $last;
    public function __construct(string $first,  string $last)
    {
        $first = strtolower(trim($first));
        $last = strtolower(trim($last));

        self::validate($first, $last);

        $this->first = $first;
        $this->last = $last;
    }

    public static function validate(string $first, string $last)
    {
        if (strcasecmp($first, $last) === 0) {
            throw new InvalidArgumentException("First and last name cannot be the same.");
        }
        if ($first === "" || $last === "") {
            throw new InvalidArgumentException("First and Last name cannot be empty.");
        }
    }

    public static function fromString(string $first, string $last): FullName
    {
        self::validate($first, $last);
        return new self($first, $last);
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

    public function __toString(): string
    {
        return "{$this->first()} {$this->last}";
    }
}
