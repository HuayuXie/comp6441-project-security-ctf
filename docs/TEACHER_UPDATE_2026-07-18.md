# COMP6441 Project Progress Update - 18 July 2026

## Current Build

The local CTF lab contains four working challenges:

1. Cookie role bypass
2. Reflected XSS
3. Path traversal and file disclosure
4. SQL injection

Each challenge includes progressive hints, a flag, completion tracking, and a secure comparison.

## Changes in This Version

- Enforced defence unlocking on the server, including direct secure URLs.
- Corrected false-positive completion paths in the XSS and SQL injection challenges.
- Changed progress reset to a POST action.
- Added Windows PowerShell setup instructions.
- Expanded automated coverage from 6 tests to 11 tests.

## Verification

The project compiles successfully and all 11 automated tests pass. The tests cover the four intended exploits, the four secure comparisons, completion tracking, progressive hints, reset behaviour, locked routes, and false-positive cases.

## Feedback Requested

- Is the current four-challenge scope appropriate for the project?
- Is the attack-versus-defence comparison detailed enough?
- Which part would be most useful to demonstrate in the five-minute presentation?

## Next Milestone

After feedback, the next version will include another beginner workflow check, final report corrections, and the presentation draft.
