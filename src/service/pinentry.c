/* SPDX-License-Identifier: Apache-2.0
 * Noninteractive Assuan endpoint. The only secret input is an inherited,
 * seekable anonymous file descriptor, never argv or a plaintext file path.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static char *read_secret(const char *variable, size_t *length)
{
    const char *value = getenv(variable);
    char *end = NULL;
    long fd = value ? strtol(value, &end, 10) : -1;
    struct stat st;
    if (!value || !*value || *end || fd < 3 || fd > 1048576 ||
        fstat((int)fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 1 || st.st_size > 65536 ||
        st.st_uid != geteuid() || (st.st_mode & 077) || st.st_nlink != 0) {
        return NULL;
    }
    *length = (size_t)st.st_size;
    char *secret = calloc(*length + 1, 1);
    if (!secret) return NULL;
    (void)mlock(secret, *length + 1);
    ssize_t count = pread((int)fd, secret, *length, 0);
    if (count != (ssize_t)*length) { explicit_bzero(secret, *length + 1); free(secret); return NULL; }
    return secret;
}

int main(void)
{
    struct rlimit limit = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &limit);
    size_t length = 0, old_length = 0;
    char *secret = read_secret("OV_SECRET_FD", &length);
    char *old_secret = read_secret("OV_OLD_SECRET_FD", &old_length);
    if (!secret) { puts("ERR 83886179 No secure password input"); return 1; }
    const char *old_path = getenv("OV_OLD_KEY_PATH");
    const char *old_name = old_path ? strrchr(old_path, '/') : NULL;
    old_name = old_name ? old_name + 1 : old_path;
    int use_old = 0;
    char *line = NULL;
    size_t capacity = 0;
    puts("OK OctoVault pinentry ready");
    fflush(stdout);
    while (getline(&line, &capacity, stdin) >= 0) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strcmp(line, "GETPIN")) {
            const char *chosen = use_old && old_secret ? old_secret : secret;
            size_t chosen_length = use_old && old_secret ? old_length : length;
            fputs("D ", stdout);
            for (size_t i = 0; i < chosen_length; i++) {
                unsigned char c = (unsigned char)chosen[i];
                if (c == '%' || c < 32 || c == 127) printf("%%%02X", c);
                else putchar(c);
            }
            fputs("\nOK\n", stdout);
        } else if (!strncmp(line, "SETDESC ", 8)) {
            use_old = old_secret && strstr(line, "Insert password to:") &&
                (!old_name || !*old_name || strstr(line, old_name));
            puts("OK");
        } else if (!strcmp(line, "BYE")) { puts("OK"); fflush(stdout); break; }
        else if (!strncmp(line, "SET", 3) || !strncmp(line, "OPTION ", 7) ||
                 !strcmp(line, "RESET") || !strcmp(line, "CONFIRM")) puts("OK");
        else if (!strncmp(line, "GETINFO pid", 11)) printf("D %ld\nOK\n", (long)getpid());
        else puts("ERR 67109139 Unsupported command");
        fflush(stdout);
    }
    explicit_bzero(secret, length + 1);
    (void)munlock(secret, length + 1);
    free(secret); free(line);
    if (old_secret) { explicit_bzero(old_secret, old_length + 1); (void)munlock(old_secret, old_length + 1); free(old_secret); }
    return 0;
}
