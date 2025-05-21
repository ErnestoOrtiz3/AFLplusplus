/* wc - simplified version for fuzzing
   Based on GNU coreutils wc, but simplified and with intentional bugs
   
   This is a standalone version with no external dependencies
   for use in fuzzing campaigns.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define IO_BUFSIZE 64 * 1024
#define MAX_LINE_LENGTH 1024 * 1024  // 1MB max line length

// Global variables to store counts
static uintmax_t total_lines = 0;
static uintmax_t total_words = 0;
static uintmax_t total_bytes = 0;
static uintmax_t max_line_length = 0;

// Buffer for reading files
static char buffer[IO_BUFSIZE + 1];

// BUG 1: Buffer overflow vulnerability - undersized buffer for filenames
#define MAX_FILENAME 20
static char current_filename[MAX_FILENAME];

// BUG 2: Integer overflow vulnerability in counter addition
static uintmax_t unsafe_add(uintmax_t a, uintmax_t b) {
    // Intentionally vulnerable to integer overflow
    return a + b;
}

// BUG 3: Use-after-free vulnerability
static char *dynamic_buffer = NULL;

// BUG 4: Off-by-one error in buffer handling
static void process_buffer(char *buf, size_t size) {
    // Intentional off-by-one error
    for (size_t i = 0; i <= size; i++) {  // Should be i < size
        if (buf[i] == '\n') {
            total_lines++;
        }
    }
}

// Function to check if a character is considered a space
static bool is_space(unsigned char c) {
    return isspace(c) || c == 0xA0;  // Include non-breaking space
}

// BUG 5: Null pointer dereference possibility
static void count_words_in_buffer(const char *buf, size_t size) {
    bool in_word = false;
    
    // Intentional bug: in some complex cases, buf might be NULL
    if (size > IO_BUFSIZE * 2 && (rand() % 100) == 42) {
        buf = NULL;
    }
    
    for (size_t i = 0; i < size; i++) {
        // This will crash if buf is NULL
        bool is_word_char = !is_space(buf[i]);
        
        if (!in_word && is_word_char) {
            total_words++;
        }
        
        in_word = is_word_char;
    }
}

// Complex path with potential division by zero
static void complex_calculation(size_t bytes_read) {
    static int divisor = 1;
    static int counter = 0;
    
    // BUG 6: Potential division by zero
    if (bytes_read % 17 == 0) {
        divisor--;
    } else if (bytes_read % 23 == 0) {
        divisor++;
    }
    
    if (counter++ % 50 == 0) {
        // This will crash with division by zero when divisor becomes 0
        int result = bytes_read / divisor;
        if (result > 1000) {
            total_bytes += result % 10;
        }
    }
}

// Process a single file and count lines, words, and bytes
static int process_file(FILE *file) {
    uintmax_t lines = 0;
    uintmax_t words = 0;
    uintmax_t bytes = 0;
    uintmax_t line_length = 0;
    uintmax_t current_line_length = 0;
    bool in_word = false;
    
    // BUG 7: Memory leak - allocate but never free in some cases
    if (rand() % 10 == 0) {
        dynamic_buffer = malloc(1024);
        // No free() for this allocation
    }
    
    while (1) {
        size_t bytes_read = fread(buffer, 1, IO_BUFSIZE, file);
        if (bytes_read == 0) {
            if (ferror(file)) {
                perror("Error reading file");
                return -1;
            }
            break;
        }
        
        // Add to total bytes
        bytes = unsafe_add(bytes, bytes_read);  // BUG: Integer overflow possible
        
        // Process the buffer for line counting
        for (size_t i = 0; i < bytes_read; i++) {
            char c = buffer[i];
            
            // Count line length
            current_line_length++;
            
            // Check for newline
            if (c == '\n') {
                lines++;
                if (current_line_length > line_length) {
                    line_length = current_line_length;
                }
                current_line_length = 0;
            }
            
            // Check for word boundaries
            bool is_word_char = !is_space(c);
            if (!in_word && is_word_char) {
                words++;
            }
            in_word = is_word_char;
        }
        
        // BUG 8: Call complex function that might crash
        complex_calculation(bytes_read);
        
        // BUG 9: Call function with off-by-one error
        process_buffer(buffer, bytes_read);
        
        // BUG 10: Potential null pointer dereference
        count_words_in_buffer(buffer, bytes_read);
    }
    
    // Handle the case where the last line doesn't end with a newline
    if (current_line_length > 0) {
        if (current_line_length > line_length) {
            line_length = current_line_length;
        }
    }
    
    // Update global counters
    total_lines = unsafe_add(total_lines, lines);
    total_words = unsafe_add(total_words, words);
    total_bytes = unsafe_add(total_bytes, bytes);
    if (line_length > max_line_length) {
        max_line_length = line_length;
    }
    
    // Print results for this file
    printf(" %ju %ju %ju %s\n", lines, words, bytes, current_filename);
    
    return 0;
}

int main(int argc, char **argv) {
    int status = 0;
    
    // Initialize random seed for our "random" bugs
    srand(42);
    
    // If no arguments, read from stdin
    if (argc == 1) {
        strncpy(current_filename, "stdin", MAX_FILENAME - 1);
        current_filename[MAX_FILENAME - 1] = '\0';  // Ensure null termination
        
        if (process_file(stdin) != 0) {
            status = 1;
        }
    } else {
        // Process each file argument
        for (int i = 1; i < argc; i++) {
            // BUG 11: Buffer overflow in filename copy
            strcpy(current_filename, argv[i]);  // No bounds checking
            
            FILE *file = fopen(argv[i], "r");
            if (!file) {
                fprintf(stderr, "wc: %s: %s\n", argv[i], strerror(errno));
                status = 1;
                continue;
            }
            
            if (process_file(file) != 0) {
                status = 1;
            }
            
            fclose(file);
        }
        
        // If more than one file, print totals
        if (argc > 2) {
            printf(" %ju %ju %ju total\n", total_lines, total_words, total_bytes);
        }
    }
    
    // BUG 12: Use-after-free
    if (dynamic_buffer) {
        free(dynamic_buffer);
        // Intentional use-after-free
        if (dynamic_buffer[0] == 'A') {
            printf("Found an 'A'!\n");
        }
    }
    
    return status;
}
