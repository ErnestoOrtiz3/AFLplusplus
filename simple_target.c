#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Simple function with a few different paths and a potential crash
void process_data(const char *data, size_t size) {
    if (size < 4) return;
    
    // Path 1
    if (data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
        printf("Magic header found!\n");
        
        // Nested condition that could crash
        if (size >= 8 && data[7] == 'X') {
            // Crash on a specific pattern
            if (data[4] == 'C' && data[5] == 'R' && data[6] == 'S' && data[7] == 'H') {
                printf("About to crash...\n");
                char *null_ptr = NULL;
                *null_ptr = 'A'; // Crash!
            }
        }
    }
    
    // Path 2
    if (size >= 5 && data[0] == 'H' && data[4] == '!') {
        printf("Hello sequence detected\n");
        
        // Another path with potential crash
        if (size >= 10 && data[9] == 0xFF) {
            if (data[5] == 'W' && data[6] == 'O' && data[7] == 'R' && data[8] == 'L' && data[9] == 'D') {
                printf("World sequence detected\n");
            }
        }
    }
}

int main(int argc, char *argv[]) {
    // Check if we have an input file
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    // Open the input file
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
    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        perror("Failed to allocate memory");
        fclose(f);
        return 1;
    }
    
    // Read file content
    size_t bytes_read = fread(buffer, 1, file_size, f);
    fclose(f);
    
    // Process the data
    process_data(buffer, bytes_read);
    
    // Clean up
    free(buffer);
    return 0;
}
