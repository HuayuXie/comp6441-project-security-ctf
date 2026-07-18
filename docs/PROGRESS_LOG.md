# Project Progress Log

This log records completed milestones and the evidence available for each one. Upload dates show when repository evidence was created; they are not presented as a complete record of all project hours.

## 15 July 2026 - Existing Implementation Milestone

Evidence: repository commits `8508e84` to `88fb607`.

- Added four local web security challenges and four secure comparisons.
- Added session-based completion tracking and progressive hints.
- Added locked defence notes and a progress reset control.
- Added automated exploit and defence tests.
- Added the project README, safety notice, and writeup notes.

## 18 July 2026 - First Code Review Milestone

Evidence: changed source, templates, tests, README, and this dated log.

- Cloned the public repository into a clean working directory.
- Ran the original test suite and confirmed that all 6 tests passed.
- Enforced defence locking on the server so direct secure URLs cannot bypass the completion workflow.
- Changed progress reset from a GET link to a POST action.
- Prevented the word `alert` by itself from completing the XSS challenge.
- Prevented a normal username and password login from awarding the SQL injection flag.
- Added Windows PowerShell setup instructions.
- Expanded the automated suite from 6 to 11 tests.
- Ran Python compilation checks and confirmed that all 11 tests passed.

Verification command:

```bash
python -m unittest discover -s tests -v
```

Verified result:

```text
Ran 11 tests
OK
```

## Remaining Milestones

- Obtain feedback on this code-review version.
- Re-test the revised workflow with a beginner participant.
- Prepare and rehearse the five-minute presentation.
- Reconcile the final report with the repository evidence.
- Export and inspect the final report PDF and supporting files before submission.
