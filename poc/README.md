# Proof-of-concept tools

Two small programs. Both are deliberately inert.

| File | What it does |
|---|---|
| `task_probe.c` | Calls `task_for_pid()` on a target and prints whether the port was obtained. Requests the port and nothing else. |
| `poc_marker.c` | A dylib that writes one file recording the pid and uid of the process it was loaded into. No network, no persistence, no access to the host process's data. |
| `debugger.entitlements` | The entitlement used to ad-hoc self-sign `task_probe`. |

## Build

```console
$ make
```

`task_probe` is signed automatically as part of the build. The
`com.apple.security.cs.debugger` entitlement is required on the **caller** of
`task_for_pid`, and ad-hoc signing satisfies it without an Apple developer
account. Without it the probe is denied against every target and the test
produces a false negative.

## Run

Against the application under test:

```console
$ ./task_probe $(pgrep -f 'balenaEtcher.app/Contents/MacOS' | head -1)
$ DYLD_INSERT_LIBRARIES=$PWD/poc_marker.dylib POC_MARKER_PATH=/tmp/marker.txt \
    /Applications/balenaEtcher.app/Contents/MacOS/balenaEtcher
```

Against the controls, which should both refuse:

```console
$ ./task_probe $(pgrep -x Finder)
$ DYLD_INSERT_LIBRARIES=$PWD/poc_marker.dylib POC_MARKER_PATH=/tmp/ctl.txt \
    /System/Applications/Calculator.app/Contents/MacOS/Calculator
```
