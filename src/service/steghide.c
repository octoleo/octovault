/* SPDX-License-Identifier: Apache-2.0
 * steghide asks for a passphrase on its controlling terminal. This narrow
 * PTY adapter avoids steghide's command-line -p password option entirely.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#ifndef OCTOVAULT_STEGHIDE_PATH
#define OCTOVAULT_STEGHIDE_PATH "/usr/bin/steghide"
#endif

static volatile sig_atomic_t child_pid = -1;
static void cancel_child(int signal_number)
{
    if (child_pid > 0) kill(-(pid_t)child_pid, SIGKILL);
    _exit(128 + signal_number);
}

int main(int argc, char **argv)
{
    int embed = argc == 5 && !strcmp(argv[1], "embed");
    int extract = argc == 4 && !strcmp(argv[1], "extract");
    if (!embed && !extract) return 2;
    for (int i = 2; i < argc; i++) if (argv[i][0] != '/' || strchr(argv[i], '\n')) return 2;
    const char *value = getenv("OV_SECRET_FD");
    char *end = NULL;
    long fd = value ? strtol(value, &end, 10) : -1;
    struct stat st;
    if (!value || !*value || *end || fd < 3 || fd > 1048576 || fstat((int)fd, &st) ||
        !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink || (st.st_mode & 077) ||
        st.st_size < 1 || st.st_size > 65535) return 2;
    size_t size = (size_t)st.st_size;
    char *secret = calloc(size + 2, 1);
    if (!secret) return 1;
    (void)mlock(secret, size + 2);
    struct rlimit zero = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &zero);
    if (pread((int)fd, secret, size, 0) != (ssize_t)size || memchr(secret, '\n', size) || memchr(secret, '\r', size)) {
        explicit_bzero(secret, size + 2); free(secret); return 2;
    }
    secret[size] = '\n';
    int master = -1;
    struct termios terminal = {0};
    terminal.c_iflag = ICRNL;
    terminal.c_oflag = OPOST | ONLCR;
    terminal.c_cflag = CS8 | CREAD | CLOCAL;
    terminal.c_lflag = ICANON | ISIG;
    terminal.c_cc[VEOF] = 4;
    terminal.c_cc[VINTR] = 3;
    signal(SIGTERM, cancel_child); signal(SIGINT, cancel_child); signal(SIGHUP, cancel_child);
    pid_t child = forkpty(&master, NULL, &terminal, NULL);
    if (child < 0) { explicit_bzero(secret, size + 2); free(secret); return 1; }
    if (!child) {
        close((int)fd);
        unsetenv("OV_SECRET_FD"); unsetenv("OV_OLD_SECRET_FD");
        explicit_bzero(secret, size + 2);
        setenv("LC_ALL", "C", 1);
        if (embed) execl(OCTOVAULT_STEGHIDE_PATH, "steghide", "embed", "-cf", argv[2], "-ef", argv[3], "-sf", argv[4], "-f", (char *)NULL);
        else execl(OCTOVAULT_STEGHIDE_PATH, "steghide", "extract", "-sf", argv[2], "-xf", argv[3], "-f", (char *)NULL);
        _exit(127);
    }
    child_pid = child;
    char pending[4096] = {0}, chunk[1024];
    size_t used = 0;
    int prompts = 0, status = 0, finished = 0;
    time_t deadline = time(NULL) + 120;
    while (time(NULL) < deadline) {
        struct pollfd ready = {master, POLLIN, 0};
        int result = poll(&ready, 1, 200);
        if (result > 0) {
            ssize_t count = read(master, chunk, sizeof(chunk) - 1);
            if (count > 0) {
                if (used + (size_t)count >= sizeof(pending)) used = 0;
                memcpy(pending + used, chunk, (size_t)count);
                used += (size_t)count; pending[used] = 0;
                if (strcasestr(pending, "passphrase:")) {
                    if (++prompts > 2) break;
                    size_t sent = 0;
                    while (sent < size + 1) {
                        ssize_t written = write(master, secret + sent, size + 1 - sent);
                        if (written < 0 && errno == EINTR) continue;
                        if (written <= 0) break;
                        sent += (size_t)written;
                    }
                    if (sent != size + 1) break;
                    used = 0; pending[0] = 0;
                }
            }
        }
        pid_t state = waitpid(child, &status, WNOHANG);
        if (state == child) { finished = 1; break; }
        if (state < 0 && errno != EINTR) break;
    }
    if (!finished) { kill(-child, SIGKILL); while (waitpid(child, &status, 0) < 0 && errno == EINTR) {} }
    child_pid = -1;
    close(master);
    explicit_bzero(secret, size + 2); (void)munlock(secret, size + 2); free(secret);
    explicit_bzero(pending, sizeof(pending)); explicit_bzero(chunk, sizeof(chunk));
    return finished && WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
