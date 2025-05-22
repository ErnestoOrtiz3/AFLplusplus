/* tail_fuzz.c - Standalone tail implementation for fuzzing
 * Based on GNU coreutils tail, simplified for fuzzing without dependencies
 * Contains intentional bugs for fuzzer discovery
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DEFAULT_N_LINES 10
#define BUFFER_SIZE 8192
#define MAX_BUFFERS 1000

/* Line buffer structure for pipe processing */
struct linebuffer {
    char buffer[BUFFER_SIZE];
    size_t nbytes;
    size_t nlines;
    struct linebuffer *next;
};

/* Character buffer structure for byte processing */
struct charbuffer {
    char buffer[BUFFER_SIZE];
    size_t nbytes;
    struct charbuffer *next;
};

/* Global variables - no command line parsing */
static char *infile = NULL;
static int count_lines = 1;  /* 1 for lines, 0 for bytes */
static long n_units = DEFAULT_N_LINES;
static int from_start = 0;   /* 0 for tail from end, 1 for head from start */

/* BUG 1: Fixed size buffer cache - potential overflow */
static char *buffer_cache[MAX_BUFFERS];
static int cache_count = 0;

/* Write data to stdout - BUG: not checking return values */
static void write_output(const char *data, size_t len) {
    /* BUG 2: Not handling partial writes or errors */
    write(STDOUT_FILENO, data, len);
}

/* Read data safely - simplified version */
static ssize_t safe_read(int fd, void *buf, size_t count) {
    ssize_t result;

    do {
        result = read(fd, buf, count);
    } while (result < 0 && errno == EINTR);

    return result;
}

/* Dump remainder of file to stdout */
static size_t dump_remainder(int fd, size_t max_bytes) {
    char buffer[BUFFER_SIZE];
    size_t total_written = 0;
    ssize_t bytes_read;

    while (max_bytes > 0) {
        size_t to_read = (max_bytes < BUFFER_SIZE) ? max_bytes : BUFFER_SIZE;
        bytes_read = safe_read(fd, buffer, to_read);

        if (bytes_read <= 0) break;

        write_output(buffer, bytes_read);
        total_written += bytes_read;
        max_bytes -= bytes_read;
    }

    return total_written;
}

/* Process file by lines from end - BUG: multiple issues */
static int tail_lines_from_end(int fd, long n_lines) {
    struct stat st;
    char *buffer;
    off_t file_size, pos;
    ssize_t bytes_read;
    long lines_found = 0;

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    file_size = st.st_size;
    if (file_size == 0) return 0;

    /* BUG 3: No bounds checking on buffer allocation */
    buffer = malloc(BUFFER_SIZE);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    /* Start from end of file */
    pos = file_size;

    while (pos > 0 && lines_found < n_lines) {
        off_t read_start = (pos > BUFFER_SIZE) ? pos - BUFFER_SIZE : 0;
        size_t read_size = pos - read_start;

        if (lseek(fd, read_start, SEEK_SET) < 0) {
            free(buffer);
            return -1;
        }

        bytes_read = safe_read(fd, buffer, read_size);
        if (bytes_read <= 0) break;

        /* BUG 4: Off-by-one error in boundary checking */
        for (ssize_t i = bytes_read - 1; i >= 0; i--) {
            if (buffer[i] == '\n') {
                lines_found++;
                if (lines_found >= n_lines) {
                    /* BUG 5: Potential buffer overflow */
                    write_output(&buffer[i + 1], bytes_read - (i + 1));

                    /* Dump rest of file */
                    if (lseek(fd, pos, SEEK_SET) >= 0) {
                        dump_remainder(fd, file_size - pos);
                    }

                    free(buffer);
                    return 0;
                }
            }
        }

        /* BUG 6: Integer underflow potential */
        pos = read_start;
    }

    /* BUG 7: Memory leak - buffer not freed in all paths */
    return 0;
}

/* Process pipe by lines - BUG: linked list management issues */
static int pipe_lines(int fd, long n_lines) {
    struct linebuffer *first, *last, *tmp;
    size_t total_lines = 0;
    ssize_t bytes_read;

    /* BUG 8: No null pointer checks */
    first = last = malloc(sizeof(struct linebuffer));
    first->nbytes = first->nlines = 0;
    first->next = NULL;

    /* Read all input into linked list */
    while (1) {
        tmp = malloc(sizeof(struct linebuffer));
        if (!tmp) break;

        bytes_read = safe_read(fd, tmp->buffer, BUFFER_SIZE);
        if (bytes_read <= 0) {
            free(tmp);
            break;
        }

        tmp->nbytes = bytes_read;
        tmp->nlines = 0;
        tmp->next = NULL;

        /* Count newlines */
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (tmp->buffer[i] == '\n') {
                tmp->nlines++;
            }
        }

        total_lines += tmp->nlines;
        last->next = tmp;
        last = tmp;

        /* BUG 9: No bounds checking on buffer cache */
        if (cache_count < MAX_BUFFERS) {
            buffer_cache[cache_count] = malloc(bytes_read);
            if (buffer_cache[cache_count]) {
                memcpy(buffer_cache[cache_count], tmp->buffer, bytes_read);
                cache_count++;
            }
        }
    }

    /* BUG 10: Logic error in line counting */
    if (n_lines == 0) goto cleanup;

    /* Handle incomplete last line */
    if (last->nbytes > 0 && last->buffer[last->nbytes - 1] != '\n') {
        last->nlines++;
        total_lines++;
    }

    /* Skip unneeded buffers */
    for (tmp = first->next; tmp && total_lines - tmp->nlines > n_lines; tmp = tmp->next) {
        total_lines -= tmp->nlines;
    }

    /* Print remaining lines */
    if (tmp) {
        const char *start = tmp->buffer;
        const char *end = tmp->buffer + tmp->nbytes;

        if (total_lines > n_lines) {
            /* Skip some lines in first buffer */
            long skip_lines = total_lines - n_lines;
            for (long i = 0; i < skip_lines && start < end; i++) {
                /* BUG 11: Potential infinite loop */
                while (start < end && *start != '\n') start++;
                if (start < end) start++; /* Skip the newline */
            }
        }

        write_output(start, end - start);

        /* Print remaining buffers */
        for (tmp = tmp->next; tmp; tmp = tmp->next) {
            write_output(tmp->buffer, tmp->nbytes);
        }
    }

cleanup:
    /* BUG 12: Potential memory leak in cleanup */
    while (first) {
        tmp = first->next;
        free(first);
        first = tmp;
    }

    return 0;
}

/* Process pipe by bytes - BUG: similar issues to pipe_lines */
static int pipe_bytes(int fd, long n_bytes) {
    struct charbuffer *first, *last, *tmp;
    size_t total_bytes = 0;
    ssize_t bytes_read;

    first = last = malloc(sizeof(struct charbuffer));
    if (!first) return -1;

    first->nbytes = 0;
    first->next = NULL;

    /* Read all input */
    while (1) {
        tmp = malloc(sizeof(struct charbuffer));
        if (!tmp) break;

        bytes_read = safe_read(fd, tmp->buffer, BUFFER_SIZE);
        if (bytes_read <= 0) {
            free(tmp);
            break;
        }

        tmp->nbytes = bytes_read;
        tmp->next = NULL;
        total_bytes += bytes_read;

        last->next = tmp;
        last = tmp;
    }

    /* Skip unneeded buffers */
    for (tmp = first->next; tmp && total_bytes - tmp->nbytes > n_bytes; tmp = tmp->next) {
        total_bytes -= tmp->nbytes;
    }

    /* Print remaining bytes */
    if (tmp) {
        size_t start_offset = (total_bytes > n_bytes) ? total_bytes - n_bytes : 0;
        write_output(&tmp->buffer[start_offset], tmp->nbytes - start_offset);

        for (tmp = tmp->next; tmp; tmp = tmp->next) {
            write_output(tmp->buffer, tmp->nbytes);
        }
    }

    /* Cleanup */
    while (first) {
        tmp = first->next;
        free(first);
        first = tmp;
    }

    return 0;
}

/* Process file by bytes from end */
static int tail_bytes_from_end(int fd, long n_bytes) {
    struct stat st;
    char *buffer;
    off_t file_size;

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    file_size = st.st_size;
    if (file_size == 0) return 0;

    /* BUG 13: Integer overflow potential */
    off_t start_pos = (file_size > n_bytes) ? file_size - n_bytes : 0;

    if (lseek(fd, start_pos, SEEK_SET) < 0) {
        perror("lseek");
        return -1;
    }

    /* BUG 14: Not checking allocation size */
    buffer = malloc(BUFFER_SIZE);
    if (!buffer) return -1;

    ssize_t bytes_read;
    while ((bytes_read = safe_read(fd, buffer, BUFFER_SIZE)) > 0) {
        write_output(buffer, bytes_read);
    }

    free(buffer);
    return 0;
}

/* Enhanced processing with intricate code paths */
static int enhanced_tail_processing(int fd) {
    struct stat st;
    char *line_cache[1000]; /* BUG 15: Fixed size cache */
    int line_count = 0;
    long total_bytes = 0;
    int processing_mode = 0;

    if (fstat(fd, &st) < 0) return -1;

    /* BUG 16: Division by zero potential */
    if (st.st_size % (n_units + 1) == 0) {
        processing_mode = 1;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    /* Complex processing with multiple code paths */
    while ((bytes_read = safe_read(fd, buffer, BUFFER_SIZE)) > 0) {
        total_bytes += bytes_read;

        /* Intricate code path 1: Line caching for long files */
        if (st.st_size > 10000 && line_count < 1000) {
            char *line_start = buffer;
            for (ssize_t i = 0; i < bytes_read; i++) {
                if (buffer[i] == '\n') {
                    size_t line_len = &buffer[i] - line_start + 1;
                    if (line_len > 10) {
                        line_cache[line_count] = malloc(line_len + 1);
                        if (line_cache[line_count]) {
                            memcpy(line_cache[line_count], line_start, line_len);
                            line_cache[line_count][line_len] = '\0';
                            line_count++;
                        }
                    }
                    line_start = &buffer[i + 1];
                }
            }
        }

        /* Intricate code path 2: Special processing for large reads */
        if (bytes_read > 4000) {
            /* BUG 17: Use after free potential */
            if (processing_mode && line_count > 0) {
                char *temp = line_cache[line_count - 1];
                free(temp);
                /* BUG 18: Still using freed pointer */
                if (strlen(temp) > 50) {
                    processing_mode = 2;
                }
            }
        }

        /* Intricate code path 3: Dynamic mode switching */
        if (total_bytes > 50000) {
            switch (processing_mode) {
                case 0:
                    lseek(fd, 0, SEEK_SET);
                    return tail_lines_from_end(fd, n_units);
                case 1:
                    lseek(fd, 0, SEEK_SET);
                    return tail_bytes_from_end(fd, n_units);
                case 2:
                    lseek(fd, 0, SEEK_SET);
                    return pipe_lines(fd, n_units);
                default:
                    /* BUG 19: Unhandled case */
                    break;
            }
            break;
        }
    }

    /* Cleanup cache - BUG 20: Potential double free */
    for (int i = 0; i < line_count; i++) {
        if (line_cache[i]) {
            free(line_cache[i]);
            line_cache[i] = NULL;
        }
    }

    return 0;
}

/* Process from start (head-like functionality) */
static int process_from_start(int fd, long n_units) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    long units_processed = 0;

    if (count_lines) {
        /* Process lines from start */
        while ((bytes_read = safe_read(fd, buffer, BUFFER_SIZE)) > 0) {
            for (ssize_t i = 0; i < bytes_read; i++) {
                if (buffer[i] == '\n') {
                    units_processed++;
                    if (units_processed >= n_units) {
                        /* BUG 21: Off-by-one in output */
                        write_output(buffer, i + 1);
                        return 0;
                    }
                }
            }
            write_output(buffer, bytes_read);
        }
    } else {
        /* Process bytes from start */
        while (units_processed < n_units && (bytes_read = safe_read(fd, buffer, BUFFER_SIZE)) > 0) {
            long remaining = n_units - units_processed;
            long to_write = (bytes_read < remaining) ? bytes_read : remaining;

            write_output(buffer, to_write);
            units_processed += to_write;
        }
    }

    return 0;
}

/* Special edge case processing */
static int process_edge_cases(int fd) {
    char *lines[100]; /* BUG 22: Fixed array size */
    int line_count = 0;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    /* BUG 23: No bounds checking on line_count */
    while ((bytes_read = safe_read(fd, buffer, BUFFER_SIZE)) > 0 && line_count < 100) {
        char *line_start = buffer;
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (buffer[i] == '\n') {
                size_t line_len = &buffer[i] - line_start + 1;
                lines[line_count] = malloc(line_len + 1);
                if (lines[line_count]) {
                    memcpy(lines[line_count], line_start, line_len);
                    lines[line_count][line_len] = '\0';
                    line_count++;
                }
                line_start = &buffer[i + 1];
            }
        }
    }

    /* Complex processing with potential issues */
    for (int i = 0; i < line_count; i++) {
        /* BUG 24: Array bounds not checked properly */
        if (i + 1 < line_count) {
            /* BUG 25: Potential null pointer dereference */
            if (strcmp(lines[i], lines[i + 1]) == 0) {
                free(lines[i + 1]);
                lines[i + 1] = NULL;
            }
        }
    }

    /* Output last n_units lines */
    int start_idx = (line_count > n_units) ? line_count - n_units : 0;
    for (int i = start_idx; i < line_count; i++) {
        if (lines[i]) {
            write_output(lines[i], strlen(lines[i]));
            free(lines[i]);
        }
    }

    return 0;
}

/* Main function - no command line parsing */
int main(int argc, char *argv[]) {
    int fd = STDIN_FILENO;
    struct stat st;

    /* Simple argument handling */
    if (argc > 1) {
        infile = argv[1];
        fd = open(infile, O_RDONLY);
        if (fd < 0) {
            perror(infile);
            return 1;
        }
    }

    /* BUG 26: Inconsistent processing based on file characteristics */
    if (fd != STDIN_FILENO) {
        if (fstat(fd, &st) == 0) {
            if (st.st_size < 1000) {
                process_edge_cases(fd);
            } else if (st.st_size < 10000) {
                if (count_lines) {
                    if (S_ISREG(st.st_mode)) {
                        tail_lines_from_end(fd, n_units);
                    } else {
                        pipe_lines(fd, n_units);
                    }
                } else {
                    if (S_ISREG(st.st_mode)) {
                        tail_bytes_from_end(fd, n_units);
                    } else {
                        pipe_bytes(fd, n_units);
                    }
                }
            } else {
                /* BUG 27: Enhanced mode has more bugs */
                enhanced_tail_processing(fd);
            }
        }
    } else {
        /* Default processing for stdin */
        if (count_lines) {
            pipe_lines(fd, n_units);
        } else {
            pipe_bytes(fd, n_units);
        }
    }

    /* Cleanup buffer cache - BUG 28: Potential memory leak */
    for (int i = 0; i < cache_count; i++) {
        if (buffer_cache[i]) {
            free(buffer_cache[i]);
        }
    }

    if (fd != STDIN_FILENO) {
        close(fd);
    }

    return 0;
}