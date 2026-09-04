# Tests for Invoke-CompromisedMailboxIR.ps1

No tenant, no Microsoft.Graph module, no ExchangeOnlineManagement module required —
`M365Stubs.ps1` fakes every cmdlet the runbook calls.

```
pwsh -File scripts/tests/Test-PasswordReset.Unit.ps1   # the reset plumbing, in isolation
pwsh -File scripts/tests/Test-PasswordReset.E2E.ps1    # a full run against a faked tenant
```

Both exit non-zero on failure.

`Test-PasswordReset.Unit.ps1` lifts the helper functions out of the script by AST, so
it exercises the real code without running it. It covers the Graph error parser, the
`Location` header reader, the long-running-operation poller (succeeds / fails / times
out / rides out a 404 / stops on a 403), and every route combination of
`Invoke-IRPasswordReset`.

`Test-PasswordReset.E2E.ps1` runs the whole script and asserts on the operator-facing
output. The cases that matter most are the ones where containment did NOT happen: a
reset whose operation failed while the `PATCH` fallback 400s must print no password at
all, and a reset Graph accepted but never confirmed must be handed over with a warning
rather than a clean bill of health. It also asserts that forwarding and inbox rules are
never written to, and that `-WhatIf` issues no reset call.
