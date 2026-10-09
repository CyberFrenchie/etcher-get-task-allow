# balenaEtcher for macOS shipped `get-task-allow` in notarised release builds

Hardened-runtime, notarised releases of balenaEtcher from 1.18.13 through 2.1.6
were signed with `com.apple.security.get-task-allow`. Any process running as the
same user could therefore take the application's task port and read or write its
memory, and could load unsigned code into it. The same entitlements were present
on the helper binary the application runs under `sudo` to write to disk.

balena fixed the issue in 2.1.7 and published
[GHSA-2hc8-w9rq-wff2](https://github.com/balena-io/etcher/security/advisories/GHSA-2hc8-w9rq-wff2)
on 21 September 2026.

| | |
|---|---|
| **Product** | balenaEtcher for macOS |
| **Version tested** | 2.1.6 (`balenaEtcher-2.1.6-arm64.dmg`) |
| **Affected versions** | 1.18.13 through 2.1.6 |
| **Patched version** | 2.1.7 |
| **Bundle** | `io.balena.etcher` |
| **Signature** | `Developer ID Application: Balena Ltd (66H43P8FRG)` |
| **Hardened runtime** | Enabled — `CodeDirectory flags=0x10000(runtime)` |
| **Notarisation** | Accepted — `spctl -a -vvv -t exec` reports `Notarized Developer ID` |
| **Advisory** | [GHSA-2hc8-w9rq-wff2](https://github.com/balena-io/etcher/security/advisories/GHSA-2hc8-w9rq-wff2) |
| **Severity** | High, CVSS 3.1: 7.5 |
| **Status** | Fixed and publicly disclosed |

## Background

Apple's **hardened runtime** exists to stop other processes interfering with a
signed application at runtime. Two of its protections matter here:

- Another process cannot obtain the application's **task port**, so it cannot
  read or write its memory.
- The application will only load libraries signed by the same team, so
  attacker-chosen code cannot be injected into it.

Both protections can be waived by entitlement, which is legitimate during
development and is the point of `com.apple.security.get-task-allow` — it is what
allows a debugger to attach. It is not intended to ship.

## The finding

Reading the entitlements off the published release:

```console
$ codesign -d --entitlements - --xml /Applications/balenaEtcher.app
```

```
com.apple.security.get-task-allow                        true
com.apple.security.cs.disable-library-validation         true
com.apple.security.cs.allow-dyld-environment-variables   true
com.apple.security.cs.allow-unsigned-executable-memory   true
com.apple.security.cs.disable-executable-page-protection true
```

The same set is present on `Contents/Resources/etcher-util`, which is the binary
the application invokes under `sudo` to perform raw disk writes.

The combination of a shipped `get-task-allow` alongside an enabled hardened
runtime suggests a development entitlements file was used to sign the release.
That would also account for the other four being set more broadly than the
application appears to require.

## Verification

Two tests, each with a control. The control is the important part: it rules out
"that is simply how macOS behaves" as an explanation.

### Test 1 — task port acquisition

`poc/task_probe.c` calls `task_for_pid()` and reports the result. It requests
the port and does nothing else; it does not read or write the target's memory.

```
vs balenaEtcher (get-task-allow present)
  caller uid   : 501 (non-root)
  task_for_pid : SUCCESS - task port obtained (kern_return_t = 0)

vs Finder (hardened runtime, no get-task-allow)          [control]
  caller uid   : 501 (non-root)
  task_for_pid : denied (kern_return_t = 5, KERN_FAILURE)
```

Same binary, same non-root user in both cases. The only variable is the target's
entitlement.

> **A detail worth recording, because it nearly produced a false negative.**
> `task_for_pid` is gated on the **caller** as well as the target. An unentitled
> binary is denied against everything, including a target that has
> `get-task-allow`. The probe must itself carry
> `com.apple.security.cs.debugger`, which is satisfied by **ad-hoc self-signing**
> and needs no Apple developer account:
>
> ```console
> $ codesign -s - --entitlements debugger.entitlements -f task_probe
> ```
>
> The first run of this test failed for exactly this reason and briefly looked
> like evidence that the finding did not hold.

### Test 2 — unsigned library injection

`poc/poc_marker.c` builds a dylib whose only action is to write one file
recording the pid and uid it was loaded into.

```
vs balenaEtcher
  payload executed inside another process
    host executable : balenaEtcher.app/Contents/Resources/etcher-util
    uid / euid      : 501 / 501

vs Calculator.app (Apple-signed, library validation intact)   [control]
  payload did not execute - library validation held
```

Note the host executable. `DYLD_INSERT_LIBRARIES` is inherited by the
`etcher-util` child process, which is the binary the application later runs under
`sudo`.

## What this does not demonstrate

Stated explicitly so the severity is not overstated:

- **Root was not obtained.** `sudo` strips `DYLD_*` from the environment it
  passes on, so the injection shown above is not proven to survive into the
  elevated invocation.
- No attempt was made to manipulate the `sudo` invocation, substitute
  `SUDO_ASKPASS`, or capture an administrator password.
- The payload does not read or modify any application data.

## Impact

The application builds and runs `sudo -A .../etcher-util`, collecting the
password via `Contents/Resources/sudo-askpass.osascript-en.js`. Code running
inside the application controls that invocation and its environment before
elevation occurs, so an attacker already executing as the user is positioned to
influence what runs with administrator rights at the moment the user approves a
prompt they have every reason to trust.

That final step is **inferred from the application's structure and was not
demonstrated**.

Assessed as local privilege escalation potential requiring user interaction.
Severity rating was left to the vendor.

## Vendor fix

In 2.1.7, balena split the entitlements by binary. Local inspection of the
patched release confirms that `get-task-allow`, disabled library validation,
DYLD environment-variable support, and disabled executable-page protection are
absent from the main application. The privileged disk-write helper has an empty
entitlement dictionary. The main application retains the entitlements needed by
its Electron and device-access functionality, including JIT and unsigned
executable-memory support.

A useful CI check is to fail the pipeline when a release artefact carries
`get-task-allow`:

```bash
codesign -d --entitlements - --xml "$APP" 2>/dev/null \
  | grep -q 'get-task-allow' && { echo "get-task-allow in release build"; exit 1; }
```

## Reproducing

```console
$ cd poc && make
$ ./task_probe $(pgrep -f 'balenaEtcher.app/Contents/MacOS' | head -1)
$ DYLD_INSERT_LIBRARIES=$PWD/poc_marker.dylib POC_MARKER_PATH=/tmp/marker.txt \
    /Applications/balenaEtcher.app/Contents/MacOS/balenaEtcher
```

Run the same two tests against Finder and Calculator to see the controls behave
differently.

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-09-17 | Reported to `security@balena.io` with evidence and PoC source |
| 2026-09-17 | Acknowledged by balena Security |
| 2026-09-18 | **Confirmed valid.** Vendor requested disclosure be held pending a patched release |
| 2026-09-18 | Fixed in balenaEtcher 2.1.7 and patched release published |
| 2026-09-21 | [GHSA-2hc8-w9rq-wff2](https://github.com/balena-io/etcher/security/advisories/GHSA-2hc8-w9rq-wff2) published; High severity, CVSS 3.1 score 7.5 |

## Scope and conduct

All testing was static analysis and local execution against a copy of the
published release, on hardware owned by the researcher. No balena infrastructure
was contacted at any point, no account was used, and nothing was written to any
storage device. The PoC tools are deliberately inert: one requests a task port
and prints the result, the other writes a single file containing its own pid and
uid.

## Credit

Found and reported by **Sam Dalgleish**.
