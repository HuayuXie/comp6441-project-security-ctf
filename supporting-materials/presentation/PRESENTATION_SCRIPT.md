# Five-Minute Presentation Script

This script matches the eight-slide `Presentation-z5671001.pptx`. The timings total five minutes and include slide changes.

## Slide 1 - Project Overview (0:00-0:20)

This project is a local beginner-friendly web security CTF lab. I built four intentionally vulnerable challenges and matched every one with a secure comparison. I will show the project goal, the challenge sequence, two attack examples, the matching defences, and how testing improved the final version.

## Slide 2 - Goal, Learning Flow, and Scope (0:20-0:50)

The goal was to turn common web weaknesses into a safe learning sequence. Learners first attempt a vulnerability, reveal an artificial flag, and then compare the same input with a safer implementation. Everything runs locally on 127.0.0.1 with demonstration data. This keeps the work educational and lets the project explain both attacker behaviour and defensive design without targeting an external system.

## Slide 3 - Four Challenges (0:50-1:25)

The lab contains four challenges with one common theme: user-controlled input is trusted in the wrong context. The cookie task trusts client-side role state. Reflected XSS lets a search value become executable output. Path traversal lets a filename escape the intended directory. SQL injection lets login data alter query logic. Each challenge includes progressive hints, completion tracking, a flag, and an unlocked secure comparison.

## Slide 4 - Reflected XSS Example (1:25-2:05)

This screenshot shows the intended reflected XSS path. The application reads a search query and deliberately marks it as safe, so the browser interprets the payload as HTML and JavaScript instead of plain text. The artificial flag confirms that the exploit path was reached. The security lesson is the trust boundary: attacker-controlled text crossed directly into an executable browser context.

## Slide 5 - SQL Injection Example (2:05-2:40)

The SQL injection task demonstrates the same trust problem in a different context. The vulnerable login builds a query by concatenating strings, so this payload changes the WHERE clause and bypasses authentication. The lab then reveals an artificial flag. Cookie manipulation and path traversal use different inputs, but all three failures come from allowing user-controlled data to cross a sensitive boundary without the correct control.

## Slide 6 - Secure Comparisons (2:40-3:25)

The secure pages use a control matched to each context. Cookie authorisation moves to a signed session identity and a backend role lookup. XSS uses output encoding and a restrictive Content Security Policy. File access uses an allowlist and a fixed base directory. SQL injection uses placeholders and parameter binding. Direct secure URLs also return HTTP 403 until the matching challenge is completed, so the learning sequence is enforced on the server.

## Slide 7 - Iteration and Validation (3:25-4:25)

The project changed through evidence. The first build established four working exploit paths, flags, and two-level hints. Two beginner testing sessions showed that the cookie task needed clearer save-and-refresh instructions and that learners wanted visible progress and defence feedback. Final validation then found that the secure XSS policy blocked the original inline CSS. I moved the stylesheet to a same-origin file, updated the policy, added automated assertions, and reran all eleven tests successfully. This improved both usability and security.

## Slide 8 - Outcome and Questions (4:25-5:00)

The final result is a complete local learning lab rather than a production web application. Its main outcome is the controlled comparison between exploit behaviour and secure design. The project strengthened my understanding of trust boundaries, context-specific controls, user testing, and validation. Its limitations are deliberate local-demo choices, including intentionally vulnerable routes and simple demonstration credentials. I am ready to answer questions about the implementation or evidence.

## Likely Questions

- Why is the vulnerable code still included? It is isolated in a local educational lab and paired with a secure comparison.
- Why use both escaping and CSP for XSS? Escaping is the primary control; CSP adds defence in depth.
- Why lock secure pages until completion? It preserves the intended challenge-then-defence learning sequence on the server.
- What would be added next? CSRF, IDOR, secure file upload, multi-step difficulty, and broader participant testing.
