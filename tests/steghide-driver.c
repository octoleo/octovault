/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int invoke(char *helper, char *action, char *a, char *b, char *c)
{
    pid_t child = fork();
    if (!child) { if (c) execl(helper, helper, action, a, b, c, (char *)NULL); else execl(helper, helper, action, a, b, (char *)NULL); _exit(127); }
    int status = 0;
    if (child < 0 || waitpid(child, &status, 0) < 0) return 1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    char cover[4096], input[4096], output[4096], restored[4096];
    snprintf(cover, sizeof(cover), "%s/cover.bmp", argv[2]);
    snprintf(input, sizeof(input), "%s/key", argv[2]);
    snprintf(output, sizeof(output), "%s/hidden.bmp", argv[2]);
    snprintf(restored, sizeof(restored), "%s/restored", argv[2]);
    /* 128x128, 24-bit uncompressed BMP, padded row length 384. */
    unsigned char header[54] = {0x42,0x4d,0x36,0xc0,0,0,0,0,0,0,54,0,0,0,40,0,0,0,128,0,0,0,128,0,0,0,1,0,24,0};
    FILE *image = fopen(cover, "wb");
    if (!image) return 1;
    fwrite(header, 1, sizeof(header), image);
    FILE *random = fopen("/dev/urandom", "rb");
    if (!random) return 1;
    unsigned char pixels[49152];
    if (fread(pixels, 1, sizeof(pixels), random) != sizeof(pixels)) return 1;
    fwrite(pixels, 1, sizeof(pixels), image); fclose(image); fclose(random);
    const char *payload = "synthetic encrypted key payload for image round trip";
    FILE *key = fopen(input, "w"); if (!key) return 1; fputs(payload, key); fclose(key);
    int fd = memfd_create("octovault-test-secret", 0); if (fd < 3) return 1;
    if (fchmod(fd, 0600) < 0) return 1;
    const char *password = "test%passphrase!with punctuation";
    if (write(fd, password, strlen(password)) != (ssize_t)strlen(password)) return 1;
    char number[32]; snprintf(number, sizeof(number), "%d", fd); setenv("OV_SECRET_FD", number, 1);
    if (invoke(argv[1], "embed", cover, input, output)) { fputs("Image embed failed\n", stderr); return 1; }
    if (invoke(argv[1], "extract", output, restored, NULL)) { fputs("Image extract failed\n", stderr); return 1; }
    FILE *result = fopen(restored, "r"); if (!result) return 1;
    char content[256] = {0}; size_t length = fread(content, 1, sizeof(content) - 1, result); fclose(result);
    if (length != strlen(payload) || strcmp(content, payload)) return 1;
    if (ftruncate(fd, 0) || pwrite(fd, "wrong", 5, 0) != 5) return 1;
    if (!invoke(argv[1], "extract", output, restored, NULL)) { fputs("Wrong password accepted\n", stderr); return 1; }
    close(fd);
    puts("steghide: image embed/extract and wrong password tests passed using descriptor input");
    return 0;
}
