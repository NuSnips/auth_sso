<?php

use App\Domain\User\ValueObjects\FullName;

describe('FullName Value Object', function () {
    // can create a valid full name
    it('creates a valid full name', function () {
        $fullName = new FullName("John", "Doe");
        expect($fullName->first())->toBe("John")
            ->and($fullName->last())->toBe("Doe");
    });

    it('creates a valid full name using fromString()', function () {
        $fullName = FullName::fromString("Jane", "smith");
        expect($fullName)->toBeInstanceOf(FullName::class)
            ->and($fullName->first())->toBe("Jane")
            ->and($fullName->last())->toBe("Smith");
    });
    // throws an exception when first/last name are empty or are the same (case-insensitive)
    it('throws an exception when first/last names are empty or only contain white space', function ($first, $last) {
        FullName::fromString(first: $first, last: $last);
    })->throws(InvalidArgumentException::class, 'First and last name cannot be empty.')
        ->with([
            'last name is empty' => ['Jane', ''],
            'first name is empty' => ['', 'Smith'],
            'first and last names are empty' => ['', ''],
            'first name is white space only' => ['   ', 'Smith'],
            'last name is white space only' => ['Jane', '  '],
            'first and last names are white space only' => [' ', '  '],
        ]);
    // handles very long names
    it('handles very long names', function () {
        $longFirst = str_repeat("Ana", 100);
        $longLast = str_repeat("Mana", 100);
        $fullName = FullName::fromString($longFirst, $longLast);

        expect($fullName->first())->toEqualIgnoreCase($longFirst)
            ->and($fullName->last())->toEqualIgnoreCase($longLast);
    });

    // handles names with hyphens, special characters or single letter names(mary-jane, 'José', 'García',x,y)
    it('handles names with hyphens and special characters and single letter names', function ($first, $last) {
        $fullName = new FullName($first, $last);

        expect($fullName->first())->toEqualIgnoreCase($first)
            ->and($fullName->last())->toEqualIgnoreCase($last);
    })->with([
        'names with hyphens' => ['mary-jane', 'jackson'],
        'names with special characters' => ['José', 'García'],
        'names with one letter' => ['X', 'Y'],
    ]);
    // preserves white space within names
    it('preserves white space within names', function () {
        $fullName = FullName::fromString("Mary Jane", "Smith");
        expect($fullName->first())->toEqualIgnoreCase("Mary Jane");
    });
    // returns the full name
    it('returns the full name as a string when called value()', function () {
        $fullName = FullName::fromString("Jane Elizabeth", "Smith");
        expect($fullName->value())->toBeString()->toBe("Jane Elizabeth Smith");
    });
    // returns the string representative of the object
    it('returns the full name as a string when called __toString', function () {
        $fullName = FullName::fromString("Jane Elizabeth", "Smith");
        expect($fullName->__toString())->toBeString()->toBe("Jane Elizabeth Smith");
    });
});
