# Beginner Web Security CTF Lab

This COMP6441 project contains six small, beginner-friendly web security CTF challenges. Each challenge demonstrates one unsafe design, provides an intended flag path, and unlocks a secure comparison after completion. The teaching emphasis is not the flag itself: every task identifies a trust boundary, explains realistic security impact, and verifies a context-specific control.

Two beginner participants tested the original four-challenge build. Their feedback led to progressive two-level hints, clearer Cookie editing and refresh instructions, completion status on the home page, and defence notes that remain locked until the matching challenge is solved. Challenges 5 and 6 were added later and are supported by automated tests, browser evidence and code review rather than participant sessions.

## Challenges

| Challenge | Vulnerability | Main defence |
| --- | --- | --- |
| Cookie Role Bypass | Trusting a client-controlled role cookie | Backend authorisation using trusted role data |
| Reflected XSS | Rendering input as executable markup | Context-aware output encoding and CSP |
| File Disclosure | Joining an untrusted filename into a path | File allowlist and controlled path handling |
| SQL Injection | Concatenating input into a SQL query | Parameterised queries |
| IDOR Document Viewer | Loading an object by identifier without checking ownership | Object-level authorisation on every request |
| Predictable Reset Token | Deriving a reset secret from public information | Random, hashed, expiring, single-use tokens |

## Run on macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Run on Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Challenge URLs

- Home: http://127.0.0.1:5000
- Challenge 1: http://127.0.0.1:5000/challenge/1
- Challenge 2: http://127.0.0.1:5000/challenge/2
- Challenge 3: http://127.0.0.1:5000/challenge/3
- Challenge 4: http://127.0.0.1:5000/challenge/4
- Challenge 5: http://127.0.0.1:5000/challenge/5
- Challenge 6: http://127.0.0.1:5000/challenge/6
- Defence comparison: http://127.0.0.1:5000/defence

## Tests

Run the automated checks from the project folder:

```bash
python -m unittest discover -s tests -v
```

The 13 tests verify the intended exploit for every challenge, confirm that the secure comparison blocks the same technique, and check the progress and defence-unlock workflow. They also check false-positive paths, object ownership enforcement, random reset-token length, expiry/use state, and replay rejection.

## Evaluation-Informed Improvements

- Each challenge now provides a small first hint and an optional more direct second hint.
- Challenge 1 explains that the edited Cookie must be confirmed before the page is refreshed or revisited.
- The home page displays `Completed` or `Not completed` for each challenge.
- Defence sections and their direct URLs unlock only after the corresponding challenge is completed.
- Completion progress can be reset from the home page for another testing session.
- Resetting progress uses a POST action so an ordinary link or page preview cannot clear the session.
- Challenge 5 separates authentication from object-level authorisation: knowing a document ID no longer grants access in the secure route.
- Challenge 6 demonstrates why password recovery needs random, short-lived, single-use tokens even when the login password is strong.

## Project Structure

- `app.py`: Flask routes, vulnerable challenge logic, and secure comparisons
- `static/`: shared stylesheet compatible with the secure page CSP
- `templates/`: challenge and defence pages
- `files/` and `secret/`: public and hidden files for the traversal challenge
- `tests/`: automated exploit and defence checks
- `WRITEUP_TEMPLATE.md`: repeatable structure for documenting each challenge
- `SECURITY_NOTICE.md`: safe-use boundaries for the lab

## Safety

The application is intentionally vulnerable. Run it only on `127.0.0.1` in a local learning environment. Do not deploy it to a public server or reuse its vulnerable patterns in production code.
