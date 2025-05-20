/* wc - print the number of lines, words, and bytes in files
   Simplified standalone version for fuzzing
   Based on GNU coreutils wc implementation
   Original authors: Paul Rubin and David MacKenzie */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Buffer size for reading files */
#define IO_BUFSIZE (128 * 1024)

/* Unsigned integer type for line, word, and byte counts */
typedef uintmax_t count_t;

/* Structure to hold the counts for a file */
struct file_counts {
    count_t lines;
    count_t words;
    count_t bytes;
};

/* Print the counts for a file */
static void
print_counts(struct file_counts counts, const char *file)
{
    printf("%7ju %7ju %7ju %s\n",
           (uintmax_t)counts.lines,
           (uintmax_t)counts.words,
           (uintmax_t)counts.bytes,
           file ? file : "");
}

/* Count lines, words, and bytes in a file */
static struct file_counts
count_file(int fd, const char *file_name)
{
    struct file_counts counts = {0, 0, 0};
    char buf[IO_BUFSIZE];
    bool in_word = false;

    while (true) {
        ssize_t bytes_read = read(fd, buf, IO_BUFSIZE);
        if (bytes_read <= 0) {
            if (bytes_read < 0) {
                fprintf(stderr, "%s: %s\n", file_name, strerror(errno));
            }
            break;
        }

        counts.bytes += bytes_read;
        const char *p = buf;

        for (ssize_t i = 0; i < bytes_read; i++) {
            unsigned char c = *p++;

            /* Count lines */
            if (c == '\n')
                counts.lines++;

            /* Count words - a word is a sequence of non-whitespace characters */
            if (isspace(c)) {
                in_word = false;
            } else if (!in_word) {
                in_word = true;
                counts.words++;
            }
        }
    }

    return counts;
}

/* Process a file and print its counts */
static bool
process_file(const char *file_name)
{
    int fd;
    bool ok = true;

    if (!file_name || strcmp(file_name, "-") == 0) {
        fd = STDIN_FILENO;
        file_name = "stdin";
    } else {
        fd = open(file_name, O_RDONLY);
        if (fd == -1) {
            fprintf(stderr, "%s: %s\n", file_name, strerror(errno));
            return false;
        }
    }

    struct file_counts counts = count_file(fd, file_name);
    print_counts(counts, file_name);

    if (fd != STDIN_FILENO && close(fd) != 0) {
        fprintf(stderr, "%s: %s\n", file_name, strerror(errno));
        ok = false;
    }

    return ok;
}

int
main(int argc, char **argv)
{
    bool ok = true;

    /* If no files are specified, read from stdin */
    if (argc <= 1) {
        return process_file(NULL) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    /* Process each file */
    for (int i = 1; i < argc; i++) {
        ok &= process_file(argv[i]);
    }

    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
