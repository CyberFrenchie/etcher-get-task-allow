# Build the two test tools.
#
#   make            build both
#   make probe      just the task-port probe
#   make payload    just the injection payload
#
# task_probe is ad-hoc self-signed with com.apple.security.cs.debugger. That
# entitlement is required on the CALLER of task_for_pid, not only on the target,
# and ad-hoc signing needs no Apple developer account.

CC      ?= clang
CFLAGS  ?= -Wall -O2

all: task_probe poc_marker.dylib

task_probe: task_probe.c
	$(CC) $(CFLAGS) -o $@ $<
	codesign -s - --entitlements debugger.entitlements -f $@

poc_marker.dylib: poc_marker.c
	$(CC) $(CFLAGS) -dynamiclib -o $@ $<

clean:
	rm -f task_probe poc_marker.dylib
	rm -rf *.dSYM

.PHONY: all clean
