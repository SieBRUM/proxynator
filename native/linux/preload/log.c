#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "preload.h"

// PROXYNATOR_HOOK_LOG=<file>: append diagnostics there (inherited by child processes).
static int log_fd = -1;

void pn_log_init(void)
{
    const char *path = getenv("PROXYNATOR_HOOK_LOG");
    if (path != NULL && *path != '\0') {
        log_fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    }
}

void pn_log(const char *format, ...)
{
    if (log_fd < 0) {
        return;
    }
    char message[1024];
    int prefix = snprintf(message, sizeof(message), "[proxynator-preload %d] ", (int)getpid());
    if (prefix < 0) {
        prefix = 0;
    }
    va_list args;
    va_start(args, format);
    int length = vsnprintf(message + prefix, sizeof(message) - (size_t)prefix - 1, format, args);
    va_end(args);
    size_t total = (size_t)prefix + (length < 0 ? 0 : (size_t)length);
    if (total > sizeof(message) - 2) {
        total = sizeof(message) - 2;
    }
    message[total++] = '\n';
    ssize_t ignored = write(log_fd, message, total);
    (void)ignored;
}
