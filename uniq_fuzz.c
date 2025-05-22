/* uniq_fuzz.c - Standalone uniq implementation for fuzzing
 * Based on GNU coreutils uniq, simplified for fuzzing without dependencies
 * Contains intentional bugs for fuzzer discovery
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

#define MAX_LINE_LENGTH 8192
#define INITIAL_BUFFER_SIZE 1024

/* Simple line buffer structure */
struct linebuffer {
    char *buffer;
    size_t size;
    size_t length;
};

/* Global configuration - simplified, no command line parsing */
static size_t skip_fields = 0;
static size_t skip_chars = 0;
static size_t check_chars = SIZE_MAX;
static int count_occurrences = 0;
static int output_unique = 1;
static int output_first_repeated = 1;
static int output_later_repeated = 0;
static int ignore_case = 0;

/* Initialize line buffer */
static void initbuffer(struct linebuffer *lb) {
    lb->buffer = malloc(INITIAL_BUFFER_SIZE);
    if (!lb->buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    lb->size = INITIAL_BUFFER_SIZE;
    lb->length = 0;
}

/* Free line buffer */
static void freebuffer(struct linebuffer *lb) {
    free(lb->buffer);
    lb->buffer = NULL;
    lb->size = 0;
    lb->length = 0;
}

/* Read a line from file into buffer - BUG: potential buffer overflow */
static int readlinebuffer_delim(struct linebuffer *lb, FILE *fp, char delimiter) {
    int c;
    size_t pos = 0;

    if (feof(fp)) return 0;

    while ((c = fgetc(fp)) != EOF) {
        /* BUG 1: Off-by-one error - should be >= not > */
        if (pos > lb->size - 1) {
            lb->size *= 2;
            lb->buffer = realloc(lb->buffer, lb->size);
            if (!lb->buffer) {
                fprintf(stderr, "Memory reallocation failed\n");
                exit(1);
            }
        }

        lb->buffer[pos++] = c;

        if (c == delimiter) break;
    }

    if (pos == 0 && c == EOF) return 0;

    /* BUG 2: Missing delimiter at end of file handling */
    lb->length = pos;
    return 1;
}

/* Skip whitespace and return pointer to first non-whitespace */
static char *skip_whitespace(char *p, char *end) {
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }
    return p;
}

/* Skip non-whitespace and return pointer to first whitespace */
static char *skip_nonwhitespace(char *p, char *end) {
    while (p < end && *p != ' ' && *p != '\t' && *p != '\n') {
        p++;
    }
    return p;
}

/* Find the field to compare - BUG: potential null pointer dereference */
static char *find_field(struct linebuffer *line, size_t *plen) {
    char *lp = line->buffer;
    char *lim = lp + line->length - 1;

    /* Skip fields */
    for (size_t i = 0; i < skip_fields && lp < lim; i++) {
        lp = skip_whitespace(lp, lim);
        lp = skip_nonwhitespace(lp, lim);
    }

    /* Skip characters */
    for (size_t i = 0; i < skip_chars && lp < lim; i++) {
        lp++;
    }

    /* BUG 3: Integer overflow potential */
    size_t len = (lim - lp < check_chars) ? lim - lp : check_chars;

    /* BUG 4: Potential negative length */
    if (lp > lim) {
        *plen = 0;
        return lp; /* BUG: returning invalid pointer */
    }

    *plen = len;
    return lp;
}

/* Case-insensitive memory compare - BUG: doesn't handle locale properly */
static int memcasecmp_simple(const char *s1, const char *s2, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int c1 = tolower((unsigned char)s1[i]);
        int c2 = tolower((unsigned char)s2[i]);
        if (c1 != c2) return c1 - c2;
    }
    return 0;
}

/* Compare two fields - BUG: logic error in comparison */
static int different(char *old, char *new, size_t oldlen, size_t newlen) {
    /* BUG 5: Should check length first, but order is wrong for edge case */
    if (ignore_case) {
        return (oldlen != newlen) || memcasecmp_simple(old, new, oldlen);
    } else {
        /* BUG 6: Using oldlen instead of min(oldlen, newlen) */
        return (oldlen != newlen) || memcmp(old, new, oldlen);
    }
}

/* Write line to output */
static void writeline(struct linebuffer *line, int match, long linecount) {
    if (!(linecount == 0 ? output_unique
          : !match ? output_first_repeated
          : output_later_repeated)) {
        return;
    }

    if (count_occurrences) {
        printf("%7ld ", linecount + 1);
    }

    /* BUG 7: Not checking fwrite return value properly */
    fwrite(line->buffer, 1, line->length, stdout);
}

/* Swap two line buffer pointers */
static void swap_lines(struct linebuffer **a, struct linebuffer **b) {
    struct linebuffer *tmp = *a;
    *a = *b;
    *b = tmp;
}

/* Process input file - main uniq logic with bugs */
static void process_file(FILE *infile, char delimiter) {
    struct linebuffer lb1, lb2;
    struct linebuffer *thisline, *prevline;

    thisline = &lb1;
    prevline = &lb2;

    initbuffer(thisline);
    initbuffer(prevline);

    /* Read first line */
    if (!readlinebuffer_delim(prevline, infile, delimiter)) {
        goto cleanup;
    }

    size_t prevlen;
    char *prevfield = find_field(prevline, &prevlen);
    long match_count = 0;

    /* BUG 8: Potential integer overflow in match_count */
    while (!feof(infile)) {
        if (!readlinebuffer_delim(thisline, infile, delimiter)) {
            if (ferror(infile)) {
                goto cleanup;
            }
            break;
        }

        size_t thislen;
        char *thisfield = find_field(thisline, &thislen);
        int match = !different(thisfield, prevfield, thislen, prevlen);

        if (match) {
            match_count++;
            /* BUG 9: No overflow check for match_count */
        }

        if (!match || output_later_repeated) {
            writeline(prevline, match, match_count);
            swap_lines(&prevline, &thisline);
            prevfield = thisfield;
            prevlen = thislen;
            if (!match) {
                match_count = 0;
            }
        }
    }

    /* Write final line */
    writeline(prevline, 0, match_count);

cleanup:
    freebuffer(&lb1);
    freebuffer(&lb2);
}

/* Enhanced processing with more intricate code paths */
static void process_file_enhanced(FILE *infile, char delimiter) {
    struct linebuffer lb1, lb2, lb3; /* BUG 10: lb3 used but not always initialized */
    struct linebuffer *thisline, *prevline, *templine;

    thisline = &lb1;
    prevline = &lb2;
    templine = &lb3; /* May be used uninitialized */

    initbuffer(thisline);
    initbuffer(prevline);
    /* BUG 11: templine not initialized in all code paths */

    char *line_cache[1000]; /* BUG 12: Fixed size cache, potential overflow */
    size_t cache_count = 0;

    /* Complex processing with multiple code paths */
    int processing_mode = 0;
    long total_lines = 0;

    while (!feof(infile)) {
        if (!readlinebuffer_delim(thisline, infile, delimiter)) {
            break;
        }

        total_lines++;

        /* BUG 13: Potential division by zero */
        if (total_lines % (skip_fields + 1) == 0) {
            processing_mode = 1;
        }

        /* Intricate code path 1: Cache management */
        if (cache_count < 1000) {
            line_cache[cache_count] = malloc(thisline->length + 1);
            if (line_cache[cache_count]) {
                memcpy(line_cache[cache_count], thisline->buffer, thisline->length);
                line_cache[cache_count][thisline->length] = '\0';
                cache_count++;
            }
        }

        /* Intricate code path 2: Special processing for long lines */
        if (thisline->length > 100) {
            /* BUG 14: Use templine without proper initialization check */
            if (processing_mode && templine->buffer) {
                memcpy(templine->buffer, thisline->buffer, thisline->length);
                templine->length = thisline->length;
            }
        }

        /* Regular uniq processing */
        if (total_lines > 1) {
            size_t thislen, prevlen;
            char *thisfield = find_field(thisline, &thislen);
            char *prevfield = find_field(prevline, &prevlen);

            int match = !different(thisfield, prevfield, thislen, prevlen);

            if (!match) {
                writeline(prevline, 0, 0);
            }
        }

        swap_lines(&prevline, &thisline);
    }

    /* Write final line */
    if (total_lines > 0) {
        writeline(prevline, 0, 0);
    }

    /* Cleanup cache - BUG 15: Potential memory leak if interrupted */
    for (size_t i = 0; i < cache_count; i++) {
        free(line_cache[i]);
    }

    freebuffer(&lb1);
    freebuffer(&lb2);
    /* BUG 16: Not freeing lb3 in all cases */
    if (templine->buffer) {
        freebuffer(&lb3);
    }
}

/* Special processing for edge cases - more intricate paths */
static void process_special_cases(FILE *infile) {
    char buffer[4096];
    char *lines[100]; /* BUG 17: Fixed array size */
    int line_count = 0;

    /* BUG 18: No bounds checking on line_count */
    while (fgets(buffer, sizeof(buffer), infile)) {
        size_t len = strlen(buffer);
        lines[line_count] = malloc(len + 1);
        if (lines[line_count]) {
            strcpy(lines[line_count], buffer);
            line_count++;
        }
    }

    /* Complex comparison logic with bugs */
    for (int i = 0; i < line_count - 1; i++) {
        for (int j = i + 1; j < line_count; j++) {
            /* BUG 19: Potential null pointer dereference */
            if (strcmp(lines[i], lines[j]) == 0) {
                /* BUG 20: Use after free potential */
                free(lines[j]);
                lines[j] = NULL;
            }
        }
    }

    /* Output remaining lines */
    for (int i = 0; i < line_count; i++) {
        if (lines[i]) {
            printf("%s", lines[i]);
            free(lines[i]);
        }
    }
}

/* Main function - no command line parsing, uses input files */
int main(int argc, char *argv[]) {
    FILE *infile = stdin;
    char delimiter = '\n';

    /* Simple file handling - no flags */
    if (argc > 1) {
        infile = fopen(argv[1], "r");
        if (!infile) {
            fprintf(stderr, "Error opening file: %s\n", argv[1]);
            return 1;
        }
    }

    /* BUG 21: Inconsistent processing modes based on file size */
    if (infile != stdin) {
        fseek(infile, 0, SEEK_END);
        long file_size = ftell(infile);
        fseek(infile, 0, SEEK_SET);

        if (file_size < 1000) {
            process_special_cases(infile);
        } else if (file_size < 10000) {
            process_file(infile, delimiter);
        } else {
            /* BUG 22: Enhanced mode has more bugs */
            process_file_enhanced(infile, delimiter);
        }
    } else {
        /* Default processing for stdin */
        process_file(infile, delimiter);
    }

    if (infile != stdin) {
        fclose(infile);
    }

    return 0;
}
