/* Static launcher: the host loader never sees the subprocess's private libc. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ROOT "/usr/lib/security/rbw-howdy/runtime"
extern char **environ;

int main(int argc, char **argv) {
    const char *name = strrchr(argv[0], '/');
    name = name ? name + 1 : argv[0];
    const int python = strcmp(name, "python3") == 0;
    const char *binary;
    if (python) binary = ROOT "/bin/python3.real";
    else if (strcmp(name, "notify-send") == 0) binary = ROOT "/bin/notify-send.real";
    else if (strcmp(name, "v4l2-ctl") == 0) binary = ROOT "/bin/v4l2-ctl.real";
    else { fputs("rbw: unknown bundled runtime executable\n", stderr); return 126; }

    /* Keep desktop D-Bus/session variables, never dynamic-loader or Python hooks. */
    char **clean = environ;
    for (char **p = environ; *p; ++p) {
        if (!strncmp(*p, "LD_", 3) || !strncmp(*p, "PYTHON", 6) ||
            !strncmp(*p, "GLIBC_TUNABLES=", 15) || !strncmp(*p, "GCONV_PATH=", 11) ||
            !strncmp(*p, "GIO_EXTRA_MODULES=", 18) || !strncmp(*p, "GIO_MODULE_DIR=", 15))
            continue;
        *clean++ = *p;
    }
    *clean = NULL;
    if (setenv("PATH", ROOT "/bin:/usr/bin:/bin", 1) ||
        setenv("OPENBLAS_NUM_THREADS", "1", 1) ||
        setenv("GIO_MODULE_DIR", ROOT "/gio-modules", 1) ||
        setenv("GIO_EXTRA_MODULES", ROOT "/gio-modules", 1)) {
        perror("rbw runtime environment"); return 126;
    }
    char *args[(size_t)argc + 16];
    int i = 0;
    args[i++] = ROOT "/lib/ld-linux-x86-64.so.2";
    args[i++] = "--inhibit-cache";
    args[i++] = "--library-path";
    args[i++] = ROOT "/lib";
    args[i++] = "--argv0";
    args[i++] = (char *)binary;
    args[i++] = (char *)binary;
    if (python) {
        args[i++] = "-I";
        args[i++] = "-B";
        args[i++] = "-S";
        args[i++] = ROOT "/python-entry.py";
    }
    for (int j = 1; j < argc; ++j) args[i++] = argv[j];
    args[i] = NULL;
    execve(args[0], args, environ);
    fprintf(stderr, "rbw: bundled runtime exec failed: %s\n", strerror(errno));
    return 126;
}
