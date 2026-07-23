# Beginner Web Security CTF Lab - Writeup Notes

## Challenge 1: Cookie Role Bypass
- Goal: become admin and view the flag.
- Vulnerability: the server trusts a client-controlled cookie named `role`.
- Intended solution: change `role=user` to `role=admin` in browser developer tools.
- Impact: a normal user can escalate privileges.
- Defence: keep a signed user identity in the session, retrieve the role from trusted backend data, and authorise on the server.

## Challenge 2: Reflected XSS Search Page
- Goal: make user input render as HTML/JavaScript.
- Vulnerability: the template uses unsafe output rendering with `safe`.
- Intended solution: search for a simple payload such as `<script>alert(1)</script>`.
- Impact: attacker-controlled script can run in a victim browser.
- Defence: HTML output encoding, careful input handling, and Content Security Policy.

## Challenge 3: File Disclosure / Path Traversal
- Goal: read the hidden flag file outside the public folder.
- Vulnerability: user-controlled filename is joined into a file path without validation.
- Intended solution: use a path such as `../secret/flag.txt`.
- Impact: sensitive local files may be exposed.
- Defence: allowlist filenames, normalise paths, and restrict reads to a safe directory.

## Challenge 4: Simple SQL Injection
- Goal: bypass login and view the flag.
- Vulnerability: SQL query is built by directly concatenating user input.
- Intended solution: use input such as username `admin' OR '1'='1' --`.
- Impact: authentication bypass or database leakage.
- Defence: parameterised queries / prepared statements.

## Challenge 5: IDOR Document Viewer
- Goal: access the administrator's document while signed in as the student.
- Vulnerability: the server queries by document ID but omits an ownership or policy check.
- Intended solution: change `document=1001` to `document=1002`.
- Impact: authenticated users can read another user's sensitive records; authentication alone does not establish object authorisation.
- Defence: include the authenticated owner or an equivalent policy decision in every object query and deny access by default.

## Challenge 6: Predictable Password Reset Token
- Goal: satisfy the administrator reset flow without knowing the password.
- Vulnerability: the token follows the guessable pattern `<username>-<year>`.
- Intended solution: submit `admin-2026`.
- Impact: an attacker can bypass the normal login and take over an account through its recovery path.
- Defence: generate a high-entropy random token, store only its digest, set a short expiry, accept it once, and deliver it through a verified channel.
