# Swift Testing Review Checklist

Use this checklist when reviewing existing Swift Testing code.

## Behavioral Coverage

- Does each test protect a specific observable behavior?
- Are happy-path, edge-case, error-path, and regression scenarios covered where they matter?
- Would a realistic regression escape because only incidental state is asserted?

## Assertion Strength

- Do assertions verify the behavior that matters, not just that something happened?
- Would the test fail if the core behavior regressed?
- Is `#require(...)` used only to gate later assertions that would otherwise be misleading?

## Parameterization

- Do parameterized cases share one assertion shape?
- Are failing cases easy to identify from the case data?
- Should any case become its own named test because it has different setup or expectations?

## Async Reliability

- Does the test await a real async boundary instead of sleeping?
- Is there hidden shared state or order sensitivity?
- Would parallel execution expose races or flaky assumptions?

## Maintainability

- Does setup stay close enough to the behavior under test?
- Are helpers clarifying intent or hiding it?
- Are tags, traits, attachments, and bug references serving a real purpose?

## Review Bias Checks

- Do not over-focus on naming if the real problem is missing behavior coverage.
- Do not confuse more lines of tests with better protection.
- Do not recommend abstraction when inline setup is clearer.
- Do not miss the absence of a regression test after a bug fix.
