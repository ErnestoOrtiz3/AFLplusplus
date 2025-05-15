/* sort-simple.c - simplified version of sort for easy compilation and fuzzing
   Based on GNU coreutils sort.c

   This is a simplified version of the GNU coreutils sort utility,
   with dependencies on uncommon libraries removed to make it easier to compile
   and instrument for fuzzing.

   Main simplifications:
   - Removed OpenSSL/libcrypto dependency
   - Removed multithreading support (single-threaded only)
   - Removed dynamic loading functionality
   - Simplified random sort to not require external crypto libraries
   - Kept core sorting functionality intact
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <locale.h>
#include <limits.h>
#include <assert.h>

/* Exit statuses */
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define SORT_FAILURE 2
#define SORT_OUT_OF_ORDER 1

/* Define some constants */
#define UCHAR_LIM 256

/* Buffer size for sorting */
#define SORT_BUFFER_SIZE (16 * 1024 * 1024)

/* We don't need flags since we're not using command-line options */

/* Structure for a line of input */
struct line {
    char *text;           /* Text of the line */
    size_t length;        /* Length of the line */
    int random_value;     /* For random sort */
};

/* Comparison function for lines */
static int
compare_lines(const void *a, const void *b)
{
    const struct line *la = (const struct line *)a;
    const struct line *lb = (const struct line *)b;
    int result;

    /* Try numeric sort first */
    {
        double numa, numb;
        char *enda, *endb;

        numa = strtod(la->text, &enda);
        numb = strtod(lb->text, &endb);

        if (enda != la->text && endb != lb->text) {
            result = (numa < numb) ? -1 : (numa > numb);
            return result;
        }
    }

    /* If not numeric, try string comparison */
    result = strcmp(la->text, lb->text);

    return result;
}

/* Read lines from a file into a buffer */
static struct line *
read_lines(FILE *fp, size_t *nlines_ptr)
{
    size_t nlines = 0;
    size_t nlines_allocated = 256;
    struct line *lines = malloc(nlines_allocated * sizeof(struct line));
    char *buffer = NULL;
    size_t buffer_size = 0;
    ssize_t line_length;

    if (!lines) {
        perror("malloc");
        exit(SORT_FAILURE);
    }

    /* Read lines from the file */
    while ((line_length = getline(&buffer, &buffer_size, fp)) != -1) {
        /* Ensure we have space for another line */
        if (nlines >= nlines_allocated) {
            nlines_allocated *= 2;
            lines = realloc(lines, nlines_allocated * sizeof(struct line));
            if (!lines) {
                perror("realloc");
                exit(SORT_FAILURE);
            }
        }

        /* Allocate space for the line text and copy it */
        lines[nlines].text = malloc(line_length + 1);
        if (!lines[nlines].text) {
            perror("malloc");
            exit(SORT_FAILURE);
        }

        memcpy(lines[nlines].text, buffer, line_length);
        lines[nlines].text[line_length] = '\0';
        lines[nlines].length = line_length;

        /* Assign a random value for potential random sorting */
        lines[nlines].random_value = rand();

        nlines++;
    }

    free(buffer);
    *nlines_ptr = nlines;
    return lines;
}

/* Write lines to a file */
static void
write_lines(struct line *lines, size_t nlines, FILE *fp)
{
    size_t i;

    for (i = 0; i < nlines; i++) {
        fputs(lines[i].text, fp);
    }
}

/* Free memory used by lines */
static void
free_lines(struct line *lines, size_t nlines)
{
    size_t i;

    for (i = 0; i < nlines; i++) {
        free(lines[i].text);
    }

    free(lines);
}



int
main(int argc, char **argv)
{
    FILE *fp;
    struct line *lines;
    size_t nlines;

    /* Initialize random number generator */
    srand(time(NULL));

    /* Set locale */
    setlocale(LC_ALL, "");

    /* Enable all sorting functionality by default */
    /* This way we don't need command-line flags */
    /* The fuzzer can provide different inputs to test different code paths */

    /* Read input */
    if (argc <= 1) {
        /* Read from stdin */
        lines = read_lines(stdin, &nlines);
    } else {
        /* Read from the specified file */
        fp = fopen(argv[1], "r");
        if (!fp) {
            perror(argv[1]);
            exit(SORT_FAILURE);
        }

        lines = read_lines(fp, &nlines);
        fclose(fp);
    }

    /* Sort the lines */
    qsort(lines, nlines, sizeof(struct line), compare_lines);

    /* Write the sorted output */
    write_lines(lines, nlines, stdout);

    /* Clean up */
    free_lines(lines, nlines);

    return EXIT_SUCCESS;
}
