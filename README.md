# Beginner Web Security CTF Lab

This COMP6441 project contains four small, beginner-friendly web security CTF challenges. Each challenge demonstrates one unsafe design, provides an intended flag path, and unlocks a secure comparison after completion.

Two beginner participants tested the lab. Their feedback led to progressive two-level hints, clearer Cookie editing and refresh instructions, completion status on the home page, and defence notes that remain locked until the matching challenge is solved.

## Challenges

| Challenge | Vulnerability | Main defence |
| --- | --- | --- |
| Cookie Role Bypass | Trusting a client-controlled role cookie | Backend authorisation using trusted role data |
| Reflected XSS | Rendering input as executable markup | Context-aware output encoding and CSP |
| File Disclosure | Joining an untrusted filename into a path | File allowlist and controlled path handling |
| SQL Injection | Concatenating input into a SQL query | Parameterised queries |

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
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
- Defence comparison: http://127.0.0.1:5000/defence

## Tests

Run the automated checks from the project folder:

```bash
python -m unittest discover -s tests -v
```

The tests verify the intended exploit for every challenge, confirm that the secure comparison blocks the same technique, and check the progress and defence-unlock workflow.

## Evaluation-Informed Improvements

- Each challenge now provides a small first hint and an optional more direct second hint.
- Challenge 1 explains that the edited Cookie must be confirmed before the page is refreshed or revisited.
- The home page displays `Completed` or `Not completed` for each challenge.
- Defence sections unlock only after the corresponding challenge is completed.
- Completion progress can be reset from the home page for another testing session.

## Project Structure

- `app.py`: Flask routes, vulnerable challenge logic, and secure comparisons
- `templates/`: challenge and defence pages
- `files/` and `secret/`: public and hidden files for the traversal challenge
- `tests/`: automated exploit and defence checks
- `WRITEUP_TEMPLATE.md`: repeatable structure for documenting each challenge
- `SECURITY_NOTICE.md`: safe-use boundaries for the lab

## Safety

The application is intentionally vulnerable. Run it only on `127.0.0.1` in a local learning environment. Do not deploy it to a public server or reuse its vulnerable patterns in production code.
