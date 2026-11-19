/* Test-image-only native PAM module. Never install this on a host. */
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    char state[32] = {0};
    struct stat metadata;
    int control = open("/run/face-smoke/result", O_RDONLY | O_NOFOLLOW);
    if (control < 0)
        return PAM_AUTH_ERR;
    if (fstat(control, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != 0 || (metadata.st_mode & 0022) != 0) {
        close(control);
        return PAM_AUTH_ERR;
    }
    ssize_t length = read(control, state, sizeof(state) - 1);
    close(control);
    if (length <= 0)
        return PAM_AUTH_ERR;
    state[strcspn(state, "\r\n")] = '\0';

    pid_t descendant = 0;
    if (strcmp(state, "block") == 0) {
        descendant = fork();
        if (descendant < 0)
            return PAM_ABORT;
        if (descendant == 0) {
            for (;;)
                pause();
        }
    }
    /* Non-secret receipt only; unlike result, events grants no authority. */
    int events = open("/run/face-smoke/events", O_WRONLY | O_APPEND | O_NOFOLLOW);
    if (events >= 0) {
        dprintf(events, "%s %ld %ld\n", state, (long)getpid(), (long)descendant);
        close(events);
    }
    if (descendant > 0) {
        for (;;)
            pause();
    }
    if (strcmp(state, "success") == 0)
        return PAM_SUCCESS;
    if (strcmp(state, "abort") == 0)
        return PAM_ABORT;
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                            int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
