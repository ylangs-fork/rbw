/* DISPOSABLE CONTAINER ONLY. No human, camera, or biometric assurance.
 * Derived from tests/pam_howdy_smoke.c. Uses the real native PAM ABI,
 * but deliberately waits for a root-owned test control before succeeding.
 */
#define _POSIX_C_SOURCE 200809L
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void receipt(const char *state) {
    int fd = open("/run/face-smoke/events", O_WRONLY | O_APPEND | O_NOFOLLOW);
    if (fd >= 0) {
        dprintf(fd, "%s %ld\n", state, (long)getpid());
        close(fd);
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    receipt("entered");
    const struct timespec interval = {0, 100000000};
    for (unsigned attempt = 0; attempt < 300; ++attempt) {
        char state[32] = {0};
        struct stat metadata;
        int fd = open("/run/face-smoke/result", O_RDONLY | O_NOFOLLOW);
        if (fd < 0)
            return PAM_AUTH_ERR;
        if (fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
            metadata.st_uid != 0 || (metadata.st_mode & 0022) != 0) {
            close(fd);
            return PAM_AUTH_ERR;
        }
        ssize_t size = read(fd, state, sizeof(state) - 1);
        close(fd);
        if (size <= 0)
            return PAM_AUTH_ERR;
        state[strcspn(state, "\r\n")] = '\0';
        if (strcmp(state, "success") == 0) {
            receipt("success");
            return PAM_SUCCESS;
        }
        if (strcmp(state, "wait") != 0) {
            receipt("denied");
            return PAM_AUTH_ERR;
        }
        nanosleep(&interval, NULL);
    }
    receipt("timeout");
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                            int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
