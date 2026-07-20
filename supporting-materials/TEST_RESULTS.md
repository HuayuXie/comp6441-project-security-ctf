# Automated Test Results

## Verification

Date: 18 July 2026  
Command:

```bash
python -m unittest discover -s tests -v
```

Result:

```text
Ran 11 tests
OK
```

## Coverage

The automated suite verifies:

- all four intended exploit paths reveal the matching flags;
- all four secure comparisons block the same attack technique;
- secure comparison routes return HTTP 403 until the matching challenge is complete;
- each challenge provides a first hint and an optional second hint;
- completion progress is recorded and can be reset;
- progress reset rejects GET and accepts POST;
- normal text containing `alert` does not complete the XSS challenge;
- a normal SQL login does not award the SQL injection flag;
- the XSS defence sends restrictive script and style CSP directives while retaining the shared stylesheet.

The Python files also passed compilation checks with:

```bash
python -m py_compile app.py tests/test_challenges.py
```
