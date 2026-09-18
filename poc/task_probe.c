/*
 * Reports whether an unprivileged, same-user process can obtain the task port
 * of a target process.
 *
 * This is the primitive that com.apple.security.get-task-allow controls. On a
 * hardened-runtime binary without that entitlement, task_for_pid() fails with
 * KERN_FAILURE (5) even for the same user; with it, the call succeeds and the
 * caller can read and write the target's memory.
 *
 * It only requests the port and reports the result. It does not read, write,
 * or otherwise touch the target's memory.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <pid>\n", argv[0]);
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);

    printf("  caller uid      : %d (root = 0)\n", getuid());
    printf("  target pid      : %d\n", pid);
    printf("  task_for_pid    : %s (kern_return_t = %d: %s)\n",
           kr == KERN_SUCCESS ? "SUCCESS - task port obtained" : "denied",
           kr, mach_error_string(kr));
    if (kr == KERN_SUCCESS) {
        printf("  implication     : this process can read and write the "
               "target's memory\n");
        mach_port_deallocate(mach_task_self(), task);
        return 0;
    }
    return 1;
}
