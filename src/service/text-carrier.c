/* Tomb-compatible text carriers for already encrypted keys.
 * SPDX-License-Identifier: Apache-2.0
 * This is reversible encoding, not encryption. Keep the original passphrase.
 */
#define _POSIX_C_SOURCE 200809L
#include <glib.h>
#include <glib/gstdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define KEY_LIMIT (1024u * 1024u)
#define CIPHER_LIMIT (256u * 1024u)
#define CARRIER_LIMIT (16u * 1024u * 1024u)

/* Tomb's cloakify alphabet order differs from the base64 alphabet order. */
static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=";

static gboolean invalid(GError **error, const char *message)
{
    g_set_error_literal(error, G_FILE_ERROR, G_FILE_ERROR_INVAL, message);
    return FALSE;
}

static char *read_bounded(const char *path, gsize limit, gsize *length, GError **error)
{
    int fd = g_open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0) {
        g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(errno),
                    "Cannot read input: %s", g_strerror(errno));
        return NULL;
    }
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size < 0 || (guint64)info.st_size > limit) {
        close(fd);
        invalid(error, "Input must be a regular file within the supported size limit.");
        return NULL;
    }
    GString *data = g_string_sized_new((gsize)info.st_size + 1);
    char chunk[8192];
    ssize_t count;
    while ((count = read(fd, chunk, sizeof(chunk))) != 0) {
        if (count < 0) {
            if (errno == EINTR) continue;
            g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(errno),
                        "Cannot read input: %s", g_strerror(errno));
            goto fail;
        }
        if ((gsize)count > limit - data->len) {
            invalid(error, "Input exceeds the supported size limit.");
            goto fail;
        }
        g_string_append_len(data, chunk, count);
    }
    close(fd);
    *length = data->len;
    return g_string_free(data, FALSE);
fail:
    close(fd);
    g_string_free(data, TRUE);
    return NULL;
}

/* Python's text helpers accept LF, CRLF and CR. Normalize only line endings;
 * spaces and Unicode inside each token remain part of the exact word map.
 */
static char **text_lines(const char *text, gsize length, gsize *count, GError **error)
{
    if (!g_utf8_validate(text, length, NULL)) {
        invalid(error, "Text contains invalid UTF-8 or a NUL byte.");
        return NULL;
    }
    char *normalized = g_malloc(length + 1);
    gsize written = 0;
    for (gsize i = 0; i < length; i++) {
        if (text[i] == '\r') {
            normalized[written++] = '\n';
            if (i + 1 < length && text[i + 1] == '\n') i++;
        } else normalized[written++] = text[i];
    }
    normalized[written] = '\0';
    char **lines = g_strsplit(normalized, "\n", -1);
    g_free(normalized);
    *count = g_strv_length(lines);
    if (*count && !*lines[*count - 1]) (*count)--;
    for (gsize i = 0; i < *count; i++) {
        if (!*lines[i]) {
            g_strfreev(lines);
            invalid(error, "Text contains a blank line.");
            return NULL;
        }
    }
    return lines;
}

static char **load_cipher(const char *path, GHashTable *lookup, GError **error)
{
    gsize length, count;
    char *data = read_bounded(path, CIPHER_LIMIT, &length, error);
    if (!data) return NULL;
    char **lines = text_lines(data, length, &count, error);
    g_free(data);
    if (!lines) return NULL;
    if (count < sizeof(alphabet) - 1) {
        g_strfreev(lines);
        invalid(error, "A cipher requires at least 65 unique, nonempty lines.");
        return NULL;
    }
    for (gsize i = 0; i < count; i++) {
        if (g_hash_table_contains(lookup, lines[i])) {
            g_hash_table_remove_all(lookup);
            g_strfreev(lines);
            invalid(error, "A cipher must not contain duplicate lines.");
            return NULL;
        }
        g_hash_table_insert(lookup, lines[i], GSIZE_TO_POINTER(i + 1));
    }
    return lines;
}

static char *encode(const char *input, gsize length, char **cipher,
                    gsize *output_length, GError **error)
{
    char *base64 = g_base64_encode((const guchar *)input, length);
    GString *output = g_string_new(NULL);
    for (const char *p = base64; *p; p++) {
        const char *token = cipher[strchr(alphabet, *p) - alphabet];
        gsize size = strlen(token);
        if (size + 1 > CARRIER_LIMIT - output->len) {
            g_free(base64);
            g_string_free(output, TRUE);
            invalid(error, "Encoded carrier exceeds the supported size limit.");
            return NULL;
        }
        g_string_append_len(output, token, size);
        g_string_append_c(output, '\n');
    }
    g_free(base64);
    *output_length = output->len;
    return g_string_free(output, FALSE);
}

static char *decode(const char *input, gsize length, GHashTable *lookup,
                    gsize *output_length, GError **error)
{
    gsize count;
    char **lines = text_lines(input, length, &count, error);
    if (!lines) return NULL;
    GString *base64 = g_string_sized_new(count);
    for (gsize i = 0; i < count; i++) {
        gsize symbol = GPOINTER_TO_SIZE(g_hash_table_lookup(lookup, lines[i]));
        if (!symbol || symbol > sizeof(alphabet) - 1) {
            invalid(error, "Carrier contains a word absent from the encoding alphabet.");
            g_strfreev(lines);
            g_string_free(base64, TRUE);
            return NULL;
        }
        g_string_append_c(base64, alphabet[symbol - 1]);
    }
    g_strfreev(lines);
    guchar *decoded = g_base64_decode(base64->str, output_length);
    char *canonical = g_base64_encode(decoded, *output_length);
    gboolean valid = *output_length <= KEY_LIMIT && !strcmp(canonical, base64->str);
    g_free(canonical);
    g_string_free(base64, TRUE);
    if (!valid) {
        g_free(decoded);
        invalid(error, "Carrier is truncated, malformed, or exceeds the key size limit.");
        return NULL;
    }
    return (char *)decoded;
}

int main(int argc, char **argv)
{
    if (argc != 5 || (strcmp(argv[1], "encode") && strcmp(argv[1], "decode"))) {
        fputs("Usage: text-carrier encode|decode INPUT CIPHER OUTPUT\n", stderr);
        return 2;
    }
    gboolean encoding = !strcmp(argv[1], "encode");
    GError *error = NULL;
    GHashTable *lookup = g_hash_table_new(g_str_hash, g_str_equal);
    char **cipher = load_cipher(argv[3], lookup, &error);
    char *input = NULL, *output = NULL;
    gsize input_length = 0, output_length = 0;
    gboolean success = FALSE;
    if (!cipher) goto done;
    input = read_bounded(argv[2], encoding ? KEY_LIMIT : CARRIER_LIMIT, &input_length, &error);
    if (!input) goto done;
    output = encoding ? encode(input, input_length, cipher, &output_length, &error)
                      : decode(input, input_length, lookup, &output_length, &error);
    if (!output) goto done;
    /* Validate everything before opening the destination. Atomic replacement
     * preserves existing output if a carrier or cipher is malformed.
     */
    success = g_file_set_contents_full(argv[4], output, output_length,
        G_FILE_SET_CONTENTS_CONSISTENT | G_FILE_SET_CONTENTS_DURABLE, 0600, &error);
done:
    if (!success) fprintf(stderr, "Text carrier: %s\n", error ? error->message : "Conversion failed.");
    g_clear_error(&error);
    g_free(input);
    g_free(output);
    g_hash_table_destroy(lookup);
    g_strfreev(cipher);
    return success ? 0 : 1;
}
