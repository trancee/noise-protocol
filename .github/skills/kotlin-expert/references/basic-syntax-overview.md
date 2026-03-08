# Kotlin Basic Syntax Overview

This reference condenses the official Kotlin basic syntax page into the concepts most likely to be needed during chat.

## Core Structure

- Package declarations go at the top of the file.
- Imports follow the package declaration.
- A runnable program entry point is usually `fun main()` or `fun main(args: Array<String>)`.

## Declarations

- Use `val` for read-only variables.
- Use `var` only when reassignment is required.
- Kotlin supports type inference, so explicit types are optional when the initializer is clear.
- A variable declared without an initializer needs an explicit type.

## Functions

- Standard form: `fun sum(a: Int, b: Int): Int { return a + b }`
- Expression body form: `fun sum(a: Int, b: Int) = a + b`
- `Unit` return types can usually be omitted.

## Classes

- Define a class with `class`.
- Constructor properties can be declared inline, for example `class Rectangle(val height: Double, val length: Double)`.
- Classes are `final` by default; use `open` to allow inheritance.

## Strings And Output

- Use `print()` and `println()` for standard output.
- Use string templates like `$name` and `${expression}` instead of manual concatenation.

## Control Flow

- `if` can be used as a statement or expression.
- `when` is Kotlin's structured multi-branch conditional.
- Use `for` with collections, indices, ranges, and progressions.
- Use `while` when loop termination depends on changing state.

## Collections And Ranges

- Iterate directly over collections when you do not need indexes.
- Use `in` and `!in` for membership and range checks.
- Common transformations use collection pipelines like `filter`, `sortedBy`, `map`, and `forEach`.

## Null Safety And Type Checks

- Nullable types use `?`, for example `Int?`.
- Check for `null` before dereferencing nullable values.
- Use `is` and `!is` for type checks; Kotlin performs smart casts after safe checks.

## Beginner Pitfalls

- Writing Java-style verbose Kotlin when expression bodies or type inference are clearer.
- Using `var` by default instead of starting with `val`.
- Forgetting that nullable values must be handled explicitly.
- Adding framework-specific advice when the question is only about language syntax.

## Source

- Official guide: https://kotlinlang.org/docs/basic-syntax.html
