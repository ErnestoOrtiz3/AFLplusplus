/* split_fuzz.c - Standalone split implementation for fuzzing
 * Based on GNU coreutils split, simplified for fuzzing without dependencies
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

#define DEFAULT_LINES 1000
#define DEFAULT_BYTES 1024
#define BUFFER_SIZE 8192
#define MAX_SUFFIX_LENGTH 10

/* Split modes - simplified */
enum split_type {
    SPLIT_LINES,
    SPLIT_BYTES,
    SPLIT_LINE_BYTES
};

/* Global variables - no command line parsing */
static char *infile = NULL;
static char *outbase = "x";
static char *outfile = NULL;
static size_t suffix_length = 2;
static char suffix_alphabet[] = "abcdefghijklmnopqrstuvwxyz";
static int output_fd = -1;
static enum split_type split_mode = SPLIT_LINES;
static long split_size = DEFAULT_LINES;
static int files_created = 0;

/* BUG 1: Fixed size suffix index array - potential overflow */
static int suffix_index[MAX_SUFFIX_LENGTH];

/* Initialize suffix generation */
static void init_suffix(void) {
    for (int i = 0; i < suffix_length; i++) {
        suffix_index[i] = 0;
    }
}

/* Generate next output filename - BUG: buffer overflow potential */
static void next_filename(void) {
    static int first_call = 1;

    if (first_call) {
        size_t base_len = strlen(outbase);
        /* BUG 2: No bounds checking on allocation size */
        outfile = malloc(base_len + suffix_length + 1);
        if (!outfile) {
            fprintf(stderr, "Memory allocation failed\n");
            exit(1);
        }
        strcpy(outfile, outbase);
        first_call = 0;
    }

    /* Generate suffix */
    char *suffix_start = outfile + strlen(outbase);
    for (int i = 0; i < suffix_length; i++) {
        suffix_start[i] = suffix_alphabet[suffix_index[i]];
    }
    suffix_start[suffix_length] = '\0';

    /* Increment suffix - BUG 3: No overflow check */
    int carry = 1;
    for (int i = suffix_length - 1; i >= 0 && carry; i--) {
        suffix_index[i]++;
        if (suffix_index[i] >= 26) {
            suffix_index[i] = 0;
        } else {
            carry = 0;
        }
    }

    /* BUG 4: No check if all suffixes exhausted */
}

/* Create new output file */
static int create_output_file(void) {
    if (output_fd >= 0) {
        close(output_fd);
    }

    next_filename();
    output_fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (output_fd < 0) {
        perror(outfile);
        return -1;
    }

    files_created++;
    return 0;
}

/* Write data to current output file */
static ssize_t write_output(const char *data, size_t len) {
    if (output_fd < 0) {
        if (create_output_file() < 0) {
            return -1;
        }
    }

    /* BUG 5: Not handling partial writes */
    return write(output_fd, data, len);
}

/* Split by lines - BUG: multiple issues */
static void split_by_lines(FILE *input, long lines_per_file) {
    char buffer[BUFFER_SIZE];
    long current_lines = 0;
    int new_file = 1;

    while (fgets(buffer, sizeof(buffer), input)) {
        if (new_file) {
            if (create_output_file() < 0) {
                return;
            }
            new_file = 0;
            current_lines = 0;
        }

        /* BUG 6: Not checking write return value */
        write_output(buffer, strlen(buffer));
        current_lines++;

        /* BUG 7: Off-by-one error in line counting */
        if (current_lines > lines_per_file) {
            new_file = 1;
        }
    }
}

/* Split by bytes - BUG: buffer management issues */
static void split_by_bytes(FILE *input, long bytes_per_file) {
    char buffer[BUFFER_SIZE];
    long current_bytes = 0;
    int new_file = 1;
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input)) > 0) {
        char *ptr = buffer;
        size_t remaining = bytes_read;

        while (remaining > 0) {
            if (new_file) {
                if (create_output_file() < 0) {
                    return;
                }
                new_file = 0;
                current_bytes = 0;
            }

            /* BUG 8: Integer overflow potential */
            long can_write = bytes_per_file - current_bytes;
            if (can_write <= 0) {
                new_file = 1;
                continue;
            }

            size_t to_write = (remaining < can_write) ? remaining : can_write;

            /* BUG 9: Not handling write errors */
            write_output(ptr, to_write);

            ptr += to_write;
            remaining -= to_write;
            current_bytes += to_write;
        }
    }
}

/* Split by line bytes - complex logic with bugs */
static void split_by_line_bytes(FILE *input, long max_bytes) {
    char *line_buffer = NULL;
    size_t line_buffer_size = 0;
    ssize_t line_length;
    long current_bytes = 0;
    int new_file = 1;

    /* BUG 10: Using getline without proper error checking */
    while ((line_length = getline(&line_buffer, &line_buffer_size, input)) != -1) {
        if (new_file || current_bytes + line_length > max_bytes) {
            if (create_output_file() < 0) {
                break;
            }
            new_file = 0;
            current_bytes = 0;
        }

        /* BUG 11: Potential buffer overflow with long lines */
        write_output(line_buffer, line_length);
        current_bytes += line_length;
    }

    /* BUG 12: Memory leak - not freeing line_buffer */
}

/* Enhanced processing with more intricate code paths */
static void enhanced_split_processing(FILE *input) {
    char buffer[BUFFER_SIZE];
    char *line_cache[1000]; /* BUG 13: Fixed size cache */
    int cache_count = 0;
    long total_bytes = 0;
    int processing_mode = 0;

    /* Determine file size for processing mode selection */
    fseek(input, 0, SEEK_END);
    long file_size = ftell(input);
    fseek(input, 0, SEEK_SET);

    /* BUG 14: Division by zero potential */
    if (file_size % (split_size + 1) == 0) {
        processing_mode = 1;
    }

    /* Complex processing with multiple code paths */
    while (fgets(buffer, sizeof(buffer), input)) {
        size_t line_len = strlen(buffer);
        total_bytes += line_len;

        /* Intricate code path 1: Line caching */
        if (cache_count < 1000 && line_len > 10) {
            line_cache[cache_count] = malloc(line_len + 1);
            if (line_cache[cache_count]) {
                strcpy(line_cache[cache_count], buffer);
                cache_count++;
            }
        }

        /* Intricate code path 2: Special processing for long lines */
        if (line_len > 100) {
            /* BUG 15: Use after free potential */
            if (processing_mode && cache_count > 0) {
                char *temp = line_cache[cache_count - 1];
                free(temp);
                /* BUG 16: Still using freed pointer */
                if (strlen(temp) > 50) {
                    processing_mode = 2;
                }
            }
        }

        /* Intricate code path 3: Dynamic mode switching */
        if (total_bytes > 5000) {
            switch (processing_mode) {
                case 0:
                    split_by_lines(input, split_size);
                    break;
                case 1:
                    split_by_bytes(input, split_size);
                    break;
                case 2:
                    split_by_line_bytes(input, split_size);
                    break;
                default:
                    /* BUG 17: Unhandled case */
                    break;
            }
            break;
        }
    }

    /* Cleanup cache - BUG 18: Potential double free */
    for (int i = 0; i < cache_count; i++) {
        if (line_cache[i]) {
            free(line_cache[i]);
            line_cache[i] = NULL;
        }
    }
}

/* Special edge case processing */
static void process_edge_cases(FILE *input) {
    char *lines[100]; /* BUG 19: Fixed array size */
    int line_count = 0;
    char buffer[4096];

    /* BUG 20: No bounds checking on line_count */
    while (fgets(buffer, sizeof(buffer), input) && line_count < 100) {
        size_t len = strlen(buffer);
        lines[line_count] = malloc(len + 1);
        if (lines[line_count]) {
            strcpy(lines[line_count], buffer);
            line_count++;
        }
    }

    /* Complex processing with potential issues */
    for (int i = 0; i < line_count; i++) {
        /* BUG 21: Array bounds not checked properly */
        if (i + 1 < line_count) {
            /* BUG 22: Potential null pointer dereference */
            if (strcmp(lines[i], lines[i + 1]) == 0) {
                free(lines[i + 1]);
                lines[i + 1] = NULL;
            }
        }
    }

    /* Output processing */
    int output_count = 0;
    for (int i = 0; i < line_count; i++) {
        if (lines[i]) {
            if (output_count % split_size == 0) {
                create_output_file();
            }
            write_output(lines[i], strlen(lines[i]));
            output_count++;
            free(lines[i]);
        }
    }
}

/* Main function - no command line parsing */
int main(int argc, char *argv[]) {
    FILE *input = stdin;

    /* Simple argument handling */
    if (argc > 1) {
        infile = argv[1];
        input = fopen(infile, "r");
        if (!input) {
            perror(infile);
            return 1;
        }
    }

    if (argc > 2) {
        outbase = argv[2];
    }

    init_suffix();

    /* BUG 23: Inconsistent processing based on file characteristics */
    if (input != stdin) {
        struct stat st;
        if (fstat(fileno(input), &st) == 0) {
            if (st.st_size < 1000) {
                process_edge_cases(input);
            } else if (st.st_size < 10000) {
                split_by_lines(input, split_size);
            } else {
                /* BUG 24: Enhanced mode has more bugs */
                enhanced_split_processing(input);
            }
        }
    } else {
        /* Default processing for stdin */
        split_by_lines(input, split_size);
    }

    /* Cleanup */
    if (output_fd >= 0) {
        close(output_fd);
    }

    if (input != stdin) {
        fclose(input);
    }

    if (outfile) {
        free(outfile);
    }

    return 0;
}
