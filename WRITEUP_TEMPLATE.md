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
