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
- Captured current attack, defence, route-locking, and progress evidence.
- Moved the shared stylesheet to a same-origin static file after visual testing showed that the secure XSS CSP correctly blocked the old inline style block.
- Added `style-src 'self'` to the secure XSS CSP and extended the test suite to verify the policy and stylesheet link.

Verification command:

```bash
python -m unittest discover -s tests -v
```

Verified result:

```text
Ran 11 tests
OK
```

## 18 July 2026 - Final Packaging Milestone

Evidence: `supporting-materials/`, the final report package, the presentation package, and the final automated checks.

- Reconciled the report with the current code, 11-test result, user-testing evidence, and current screenshots.
- Produced and visually inspected the final report DOCX and 20-page PDF.
- Produced an eight-slide presentation with speaker notes, a fixed-layout PDF, and a timed five-minute script.
- Added a current evidence catalogue, automated test record, anonymous user-testing summary, and presentation copies.
- Prepared a clean source ZIP from the final local commit.

## Manual Submission Steps

- Confirm the student's exact name on the report and presentation covers.
- Confirm the exact Moodle upload fields, filename rules, and deadline shown for the course.
- Push the final local commits to the public repository after explicit approval.
- Upload the report and any separately requested presentation or supporting files to Moodle.
