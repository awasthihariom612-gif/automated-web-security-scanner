# Manual Test Plan

Do these tests only against a site you own or are authorized to assess.

| Test | Action | Expected result |
|---|---|---|
| Valid HTTPS target | Run `python scanner.py https://example.com` | Scan completes if target is reachable; JSON and CSV are created |
| Missing header | Use an authorized test site that omits a header | Header is shown as MISSING with a recommendation |
| Invalid hostname | Run `python scanner.py https://this-domain-should-not-exist.invalid` | Helpful resolution error; report files are written |
| Timeout | Use a permitted test endpoint that deliberately responds slowly, if available | Timeout message after configured limit |
| HTTP target | Run against an authorized public HTTP endpoint | HTTPS check is false; note that HTTP is unencrypted |
| Redirect | Run against an authorized URL that redirects | Redirect is not followed; scan destination separately |

Record your actual date, target, result, and screenshot after running each applicable test. Do not claim hypothetical results as actual results.
