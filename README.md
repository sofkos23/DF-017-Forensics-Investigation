# DF-017 login and file activity investigation

**All records, accounts, hosts, addresses and file paths are invented. The referenced files themselves are not supplied.**

## Case brief

A training evidence portal recorded repeated login failures and file-access
events on 20 October 2026. Determine which successful sessions meet the stated
rule and what subsequent downloads are recorded. Prioritise a session for
review without assuming an intrusion or attributing activity to a person.

The exports are deliberately unsorted and contain duplicate and malformed
records. Their timestamps use Z and +01:00 offsets. Assume both sources use
the same session-ID namespace. Clock accuracy, log completeness and the
real-world identity behind an account have not been independently established.

## Run from this folder

Python 3.10 or newer, standard library only. No notebook, pip install or API key.

|Purpose|macOS or Linux|Windows PowerShell|
|-|-|-|
|Run starter or full analysis|`python3 analyze\_case.py`|`py analyze\_case.py`|
|Run login stage only|`python3 analyze\_case.py --stage logins`|`py analyze\_case.py --stage logins`|
|Check function 1|`python3 check\_solution.py LoginChecks`|`py check\_solution.py LoginChecks`|
|Check function 2|`python3 check\_solution.py DownloadChecks`|`py check\_solution.py DownloadChecks`|
|Run all checks|`python3 check\_solution.py`|`py check\_solution.py`|

If Windows does not recognise `py`, use `python` after checking that
`python --version` reports Python 3.10 or newer. Otherwise install Python 3.

Implement only `find\_login\_sequences` and `correlate\_downloads` in
`analyze\_case.py`. Their docstrings are the exact contracts. The supplied
loader, evidence, manifest and tests remain unchanged.

## Rules and field meanings

1. For every SUCCESS at T, group on `(username, source\_ip, host)` and count
FAIL events where **T - 5 minutes <= time < T**. Flag at least three.
Each success is evaluated independently; earlier successes do not reset
the window. A failure may support more than one alert.
2. Join file events using **username AND host AND session\_id**. Keep only
`action == "DOWNLOAD"`, `result == "SUCCESS"`, and **T <= time <= T + 10 minutes**.
Count events, even if their paths repeat. Sum their integer bytes values.
Retain alerts with zero matches. Sort by descending byte total, then time
and success event ID. This ranking measures recorded volume, not guilt.
3. `event\_id` identifies one event within its source. `session\_id` links the
two sources. `bytes` is the transfer size recorded by the application;
independent transfer completion and destination evidence are not supplied.

## Evidence handling supplied for you

`evidence\_tools.py` verifies the original CSV byte hashes against
`evidence\_manifest.json`, trims outer whitespace, validates rows, requires
explicit timezone offsets, converts times to UTC and byte strings to integers,
and removes identical repeated event IDs. It records duplicate and rejected
CSV row numbers in `audit.json`. Conflicting versions of an ID stop analysis.
Rejected rows remain in the source; they are excluded from computed findings.

The starter writes `audit.json` before stopping at the first TODO. Function 1
adds `login\_alerts.json`; the completed program adds `summary.json`. Rerun after
every change: old output files can be stale. A hash match demonstrates agreement
with this supplied baseline; it does not establish authenticity or completeness.
`.gitattributes` preserves CSV bytes through Git on all operating systems.

## Verified results -- complete this section

|Source|Data rows excluding header|Accepted unique|Duplicate|Rejected|
|-|-|-|-|-|
|auth\_log.csv|60|54|1|5|
|file\_log.csv|35|30|1|4|

* SHA-256 check outcome and what it establishes: Both CSV evidence files passed SHA-256 verification against the supplied evidence. This shows consistency with the provided baseline, but does not independently prove the authenticity, origin, or completeness of the evidence.
* One rejected event ID and the exact rejection reason: Event A900 was rejected because of "Invalid isoformat string: 'not-a-time'".
* Number of flagged successful sessions: 3

|Success ID|Account|Session|Supporting failure IDs|Download IDs|Event count|Total bytes|
|-|-|-|-|-|-|-|
|A005|analyst01|S-104|A002, A003, A004|F001, F002, F003|3|5,509,120|
|A018|analyst02|S-304|A015, A016, A017|F013|1|2,048|
|A014|backup\_svc|S-204|A011, A012, A013|None|0|0|

## Manual evidence check -- do this without asking AI to count for you

For the highest-volume flagged session, find every supporting failure, the
success and every qualifying download in the original CSV files. Record their
original timestamps and UTC equivalents. Add rows as needed.

|Source and event ID|Original timestamp|UTC timestamp|What the row records|
|-|-|-|-|
|auth\_log.csv - A002|2026-10-20T08:58:00Z|08:58:00 UTC|Failed login, analyst01|
|auth\_log.csv - A003|2026-10-20T09:00:00Z|09:00:00 UTC|Failed login, analyst01|
|auth\_log.csv - A004|2026-10-20T10:01:00+01:00|09:01:00 UTC|Failed login, analyst01|
|auth\_log.csv - A005|2026-10-20T09:03:00Z|09:03:00 UTC|Successful login, S-104|
|file\_log.csv - F001|2026-10-20T09:05:00Z|09:05:00 UTC|Successful download, 5,242,880 bytes|
|file\_log.csv - F002|2026-10-20T10:07:00+01:00|09:07:00 UTC|Successful download, 262,144 bytes|
|file\_log.csv - F003|2026-10-20T09:13:00Z|09:13:00 UTC|Successful download, 4,096 bytes|

* Manual sum of download bytes, showing the addition: 5,242,880 (F001) + 262,144 (F002) + 4,096 (F003) = 5,509,120
* A001 versus A002: which qualifies for the A005 window and why? A002 qualifies because it happened at 08:58:00 UTC, exactly five minutes before successful login A005 at 09:03:00 UTC. A001 happened at 08:57:59 UTC, one second outside the allowed window, and is because of that excluded.
* F003 versus F004: which qualifies for the A005 follow-up and why? F003 qualifies because it happened at 09:13:00 UTC, exactly ten minutes after A005. F004 happened at 09:13:01 UTC, one second outside the follow-up window, and is excluded.
* Why F005 is excluded even though the account matches: Even though F005 belongs to the same username, its session identifier is S-OTHER,  whereas the suspicious successful login A005 belongs to session S-104. The correlation rule requires matching session identifiers.
* One +01:00 timestamp and its equivalent UTC time: Authentication event A004 has the original timestamp 2026-10-20T10:01:00+01:00, equivalent to 2026-10-20T09:01:00Z.
* One limitation of excluding malformed records: Excluding malformed records improves data consistency but can also remove potentially relevant events. This could create an incomplete reconstruction of the authentication or file activity timeline.

## Checks actually run

Command, date and actual final result (paste output, including failures if any):

```text
Date: 2 November 2026

Environment: Windows PowerShell



INITIAL TEST EXECUTION

Command: py check\_solution.py



Ran 21 tests in 0.035s

FAILED (errors=8)



Error from the initial output:

NotImplementedError: Complete correlate\_downloads



The initial run passed 13 tests. Eight tests produced errors because

correlate\_downloads() had not yet been implemented.



FINAL TEST EXECUTION

Command: py check\_solution.py



Ran 21 tests in 0.015s

OK



All 21 automated tests passed with zero failures and zero errors.



COMPLETE FORENSIC ANALYSIS

Command: py analyze\_case.py



SHA-256 checks match the supplied manifest.

auth\_log.csv: 60 rows; 54 accepted; 1 duplicate; 5 rejected.

file\_log.csv: 35 rows; 30 accepted; 1 duplicate; 4 rejected.

Saved audit.json. A hash match does not prove origin or completeness.

Found 3 login sequences; saved login\_alerts.json.

Saved summary.json. Verify event IDs against both original CSV files.

A005 analyst01 S-104: 3 failures, 3 downloads, 5509120 bytes

A018 analyst02 S-304: 3 failures, 1 downloads, 2048 bytes

A014 backup\_svc S-204: 3 failures, 0 downloads, 0 bytes
```

All 21 supplied checks should pass. Passing these checks is limited validation
of the stated classroom rule, not certification of a forensic tool.

## AI interpretation and our final finding

Prompt 3 response about the overstated claim (keep the actual response):

> The claim is overstated. The highest recorded download total does not identify an attacker or establish who operated the account. The DOWNLOAD events do not prove that evidence was stolen, that transfers completed, or that the activity was unauthorised. Matching SHA-256 hashes establish consistency with the supplied manifest, not independent authenticity or completeness.

>

> Session S-104 (analyst01, success A005) merits priority review because failures A002–A004 preceded the successful login and three qualifying downloads (F001–F003) recorded 5,509,120 bytes. These observations warrant further investigation but do not establish intrusion, theft, the identity of an operator, or the authenticity and completeness of the logs.

One claim we corrected or independently verified, with event IDs:

We independently verified that session S-104 had three qualifying downloads, not proof of evidence theft. Events A002, A003 and A004 preceded successful login A005. Downloads F001, F002 and F003 occurred within the ten-minute follow-up window and totalled 5,509,120 bytes. F004 was excluded because it occurred one second after the window ended, and F005 was excluded because its session ID did not match S-104.



Final 180-220 word finding, reviewed and edited by the pair:

The DF-017 training evidence identifies three successful login sessions meeting the rule of at least three preceding failed attempts within five minutes. Session S-104, associated with account analyst01 on DF-PORTAL01, should receive priority review because it has the highest recorded download volume.



Authentication events A002, A003 and A004 preceded successful login A005 at 09:03 UTC on 20 October 2026. Within the following ten minutes, successful DOWNLOAD events F001, F002 and F003 recorded a combined 5,509,120 bytes across three events. The final qualifying download, F003, occurred exactly at the 09:13 UTC boundary. These records demonstrate activity matching the investigation rule, not confirmed theft or unauthorised access.



For comparison, session S-304 (analyst02, A018) had three supporting failures (A015–A017) but only one qualifying download, F013, recording 2,048 bytes.



Two important limitations are that the logs have not been independently verified as complete and that recorded download events do not establish successful delivery to an external destination. A plausible benign explanation is authorised retrieval of training materials after mistyped login credentials.



Further investigation should request authentication and MFA records for the relevant sessions and independent network or destination logs to establish whether the recorded transfers completed and where the data went.

It must cite evidence IDs, separate observation from inference, include a
comparison session, two limitations, one benign explanation and two next
evidence requests. Do not claim that an account or IP identifies a person.

## AI use and pair review

* Names of both partners: Sofija Kostic and Linnea Werner
* GenAI tool/ChatGPT date and displayed model: ChatGPT, 2 November 2026, GPT-6.
* Prompts used and what they produced: Prompt 1 supported the implementation of find\_login\_sequences(), including grouping failed logins and applying the five-minute window. Prompt 2 supported correlate\_downloads(), including matching sessions and calculating download totals. Prompt 3 evaluated an overstated forensic claim and produced an interpretation. Prompt 4 supported drafting the final forensic finding for human review.
* One follow-up question or correction, with a short response excerpt: We independently checked which downloads belonged to session S-104, including the time-window boundary and session identifier. We checked the AI-assisted interpretation against the original CSV events F003, F004 and F005. Response excerpt: “F004 happened one second after the window ended, and F005 was excluded because its session ID did not match S-104.”

Results of code and evidence checks performed:  All 21 automated tests passed. Both CSV files matched their SHA-256 hashes in the supplied evidence. The program identified three flagged successful sessions. The manually verified leading session, S-104, contained three qualifying downloads with a total of 5,509,120 bytes. Duplicate and wrongly formatted records were accounted for during evidence validation.

## Submit

Submit one public repository URL per pair through the course route. Include the ten
starter project files and the newly generated `audit.json`, `login\_alerts.json`,
and `summary.json`. Complete this README. The repository needs a starting
commit and a finished commit. The accompanying student guide gives the
90-minute schedule; `GitHub\_CLI\_Guide.docx` covers setup and upload.
Only synthetic exercise files belong in this repository. Keep credentials out.

Optional stretch after the core task: use the interactive Python console to
compare `min\_failures=2` with `min\_failures=3`, without changing the defaults or
original evidence. Which extra session appears, and does that change what you
can conclude? Record this separately from the required default output.

