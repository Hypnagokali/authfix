# Contributing Guidelines 🛠️
Thanks for your interest in contributing to `Authfix`!

## Reporting Bugs
- Feel free to open an [issue][issues].

## Provide PR
1. Fork the repository and create a new branch for your feature or fix.
    - New features should first be discussed in the Idea section of [Discussions][discussions]
2. Make your changes with clear, readable code.
3. Please provide a test case for your modification, unless it's trivial.
4. Format your code using `rustfmt` before committing.
5. Write a clear commit message explaining your change. It would be nice, if it includes a semantic prefix, such as:
    - [+] Introduce a complete new feature
    - [-] Remove a feature completely
    - [FIX] Fix a bug
    - [*] Any other change to the production code
    - [DOC] Add documentation
    - [TEST] Change, fix or add tests
    - [REF] Refactoring
6. Open a pull request with a brief description of what you’ve done.

[discussions]: https://github.com/Hypnagokali/authfix/discussions/categories/ideas

## Notes 
- If you're not sure about something, feel free to open an [issue][issues] or use the [Discussions section][discussions] to discuss it first.
- CI currently runs `cargo test` and `cargo clippy --all-features --all-targets`.

## Code of Conduct
[Code of Conduct](./CODE_OF_CONDUCT.md)

[issues]: https://github.com/Hypnagokali/authfix/issues
