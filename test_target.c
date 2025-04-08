/*
 * AFL++ CPU Scheduler Test Target
 *
 * This program has multiple code paths and crash conditions
 * to help test the effectiveness of the AFL++ CPU scheduler.
 *
 * Compile with: gcc -o test_target test_target.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

// Function to check if input contains a specific pattern
bool contains_pattern(const char *input, size_t len, const char *pattern) {
    size_t pattern_len = strlen(pattern);
    if (len < pattern_len) return false;
    
    for (size_t i = 0; i <= len - pattern_len; i++) {
        if (memcmp(input + i, pattern, pattern_len) == 0) {
            return true;
        }
    }
    return false;
}

// Different code paths based on input content
void process_input(const char *input, size_t len) {
    // Path 1: Basic path
    if (len > 0) {
        printf("Processing input of length %zu\n", len);
    }
    
    // Path 2: Check first byte
    if (len > 0) {
        switch (input[0]) {
            case 'A':
                printf("Path A\n");
                break;
            case 'B':
                printf("Path B\n");
                break;
            case 'C':
                printf("Path C\n");
                break;
            default:
                printf("Other path\n");
                break;
        }
    }
    
    // Path 3: Check for specific patterns
    if (contains_pattern(input, len, "MAGIC")) {
        printf("Found MAGIC pattern\n");
        
        // Nested path
        if (contains_pattern(input, len, "MAGIC1234")) {
            printf("Found extended pattern MAGIC1234\n");
        }
    }
    
    // Path 4: Check for numeric content
    bool all_digits = true;
    for (size_t i = 0; i < len; i++) {
        if (input[i] < '0' || input[i] > '9') {
            all_digits = false;
            break;
        }
    }
    
    if (all_digits && len > 0) {
        printf("Input contains only digits\n");
        
        // Convert to number and check range
        long value = atol(input);
        if (value > 1000 && value < 2000) {
            printf("Value is between 1000 and 2000\n");
        } else if (value > 9000) {
            printf("Value is over 9000!\n");
        }
    }
    
    // Path 5: Check for specific length ranges
    if (len > 10 && len < 20) {
        printf("Input length is between 10 and 20\n");
    } else if (len > 50) {
        printf("Input is very long\n");
    }
    
    // Crash condition 1: Specific pattern causes crash
    if (contains_pattern(input, len, "CRASH_NOW")) {
        printf("About to crash...\n");
        abort();
    }
    
    // Crash condition 2: Specific sequence of bytes
    if (len >= 4 && 
        input[0] == 'B' && 
        input[1] == 'O' && 
        input[2] == 'O' && 
        input[3] == 'M') {
        
        int *null_ptr = NULL;
        *null_ptr = 1;  // Null pointer dereference
    }
    
    // Crash condition 3: Complex condition
    if (len >= 6 && 
        input[0] >= 'A' && input[0] <= 'Z' &&
        input[1] >= 'a' && input[1] <= 'z' &&
        input[2] >= '0' && input[2] <= '9' &&
        input[3] == '!' &&
        input[4] == '@' &&
        input[5] == '#') {
        
        // Stack buffer overflow
        char small_buffer[10];
        strcpy(small_buffer, input);  // Potential overflow
    }
}

int main(int argc, char *argv[]) {
    // Check command line arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    // Open input file
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("Failed to open input file");
        return 1;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    // Allocate buffer
    char *buffer = (char *)malloc(file_size + 1);
    if (!buffer) {
        perror("Failed to allocate memory");
        fclose(f);
        return 1;
    }
    
    // Read file content
    size_t bytes_read = fread(buffer, 1, file_size, f);
    buffer[bytes_read] = '\0';  // Null-terminate the buffer
    fclose(f);
    
    // Process the input
    process_input(buffer, bytes_read);
    
    // Clean up
    free(buffer);
    return 0;
}
