# Supporting Materials

This folder contains evidence for the COMP6441 Beginner Web Security CTF Lab.

## Current Build Evidence

The following screenshots were captured from the local application on 18 July 2026:

- `01-home-unsolved.png`: all four challenges before completion
- `02-server-enforced-defence-lock.png`: direct access to an unfinished secure route returns a locked page
- `03-challenge1-cookie-before.png`: Cookie Role Bypass before editing the role
- `03b-challenge1-cookie-exploit.png`: role cookie edited to `admin` and the Challenge 1 flag displayed
- `04a-challenge2-before.png`: Reflected XSS challenge before entering a payload
- `04-challenge2-xss-exploit.png`: reflected XSS payload and flag
- `05-challenge2-secure-encoding.png`: the same payload encoded as text under a restrictive CSP
- `06a-challenge3-before.png`: File Disclosure challenge reading the public file
- `06-challenge3-path-traversal-exploit.png`: path traversal reads the hidden flag file
- `07-challenge3-secure-allowlist.png`: the allowlist blocks the traversal path
- `08a-challenge4-before.png`: SQL Injection challenge before the bypass
- `08-challenge4-sqli-exploit.png`: SQL injection bypass and flag
- `09-challenge4-secure-parameterised-query.png`: the same input fails against a parameterised query
- `10-home-progress-three-completed.png`: session progress after Challenges 2-4
- `11-defence-unlock-state.png`: completed defences are open while Challenge 1 remains locked

## Earlier Implementation and User Testing Evidence

These images were retained from the report evidence collected on 15 July 2026:

- `12-participant-a-flask-log.jpg`: Participant A local request sequence
- `13-participant-b-cookie-feedback.jpg`: Participant B Cookie editing evidence
- `14-feedback-progressive-hints.png`: revised two-level Cookie hint
- `15-feedback-progress-tracker.png`: progress tracker after all four challenges

## Supporting Records

- `TEST_RESULTS.md`: automated validation command, result, and coverage
- `USER_TESTING_SUMMARY.md`: anonymous testing method, findings, changes, and limitations
- `presentation/Presentation-z5671001.pptx`: editable five-minute presentation
- `presentation/Presentation-z5671001.pdf`: fixed-layout presentation copy
- `presentation/PRESENTATION_SCRIPT.md`: timed speaking notes and likely questions

All application testing used `127.0.0.1`. No external system was scanned or attacked.
