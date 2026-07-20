# Anonymous User Testing Summary

## Method

Two beginner participants independently ran the local CTF on Windows on 15 July 2026. Each participant attempted all four challenges, used hints when needed, recorded the approximate session duration, identified the most difficult task, and suggested improvements.

Testing remained on `127.0.0.1` and used only the included artificial flags.

## Participant A

- Approximate session: 30 minutes
- Completed all four challenges
- Used hints for all four challenges
- Found Cookie Role Bypass most difficult because browser Cookie storage was unfamiliar
- Requested clearer terminology, progressive hints, and defence notes that do not reveal unfinished solutions

## Participant B

- Approximate session: 30 minutes
- Completed all four challenges
- Used hints for Challenges 1, 3, and 4
- Found Cookie Role Bypass most difficult because the page did not update immediately after editing the role
- Requested explicit confirmation and refresh instructions, a progress tracker, and multiple hint levels

## Implemented Changes

- Added a small first hint and an optional more direct second hint to every challenge.
- Added explicit confirmation and refresh instructions to the Cookie challenge.
- Added `Completed` and `Not completed` status to the home page.
- Added a progress reset control.
- Delayed defence notes until the matching challenge is complete.
- Enforced the same defence lock on direct secure URLs.

## Limitations

The sample contains only two acquaintances and is not representative of a larger learner population. The results support intended-path validation and usability improvements, but they do not establish general educational effectiveness.
