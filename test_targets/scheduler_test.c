/*
 * AFL++ Scheduler Test Target
 * --------------------------
 *
 * This is a simple program designed to test the AFL++ feedback-guided
 * CPU scheduler. It has multiple paths and potential crashes that can
 * be discovered through fuzzing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

// Function with multiple paths based on input
int process_data(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;  // Too short
    }
    
    // Path 1: Check magic bytes
    if (data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
        // Path 1.1: Special sequence
        if (size >= 8 && data[4] == 0x41 && data[5] == 0x42 && data[6] == 0x43 && data[7] == 0x44) {
            // Hard-to-reach path
            if (size >= 12 && data[8] == 0x01 && data[9] == 0x02 && data[10] == 0x03 && data[11] == 0x04) {
                // Potential crash 1 (divide by zero)
                if (size >= 13 && data[12] == 0) {
                    int result = 100 / data[12];  // Divide by zero if data[12] is 0
                    return result;
                }
                return 10;
            }
            return 5;
        }
        return 1;
    }
    
    // Path 2: Check for different magic bytes
    if (data[0] == 'T' && data[1] == 'E' && data[2] == 'S' && data[3] == 'T') {
        // Path 2.1: Process integers
        if (size >= 8) {
            int value = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
            
            // Different paths based on value
            if (value > 0 && value < 1000) {
                return 20;
            } else if (value >= 1000 && value < 10000) {
                return 21;
            } else if (value >= 10000 && value < 50000) {
                return 22;
            } else if (value == 0x12345678) {
                // Potential crash 2 (buffer overflow)
                char buffer[10];
                if (size > 20) {
                    strcpy(buffer, (char*)&data[8]);  // Potential buffer overflow
                }
                return 23;
            }
            return 24;
        }
        return 2;
    }
    
    // Path 3: Check for another magic sequence
    if (data[0] == 'C' && data[1] == 'R' && data[2] == 'A' && data[3] == 'S' && size >= 8) {
        // Path 3.1: Process crash type
        uint32_t crash_type = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
        
        switch (crash_type) {
            case 1:
                // Potential crash 3 (null pointer dereference)
                if (size > 10 && data[8] == 0xFF && data[9] == 0xFF && data[10] == 0xFF) {
                    char *ptr = NULL;
                    return *ptr;  // Null pointer dereference
                }
                return 30;
                
            case 2:
                // Potential crash 4 (out of bounds access)
                if (size > 9 && data[8] == 0xAA && data[9] == 0xBB) {
                    int array[5] = {1, 2, 3, 4, 5};
                    return array[10];  // Out of bounds access
                }
                return 31;
                
            case 3:
                // Potential crash 5 (stack overflow)
                if (size > 9 && data[8] == 0xCC && data[9] == 0xDD) {
                    char big_buffer[1024];
                    memset(big_buffer, 'A', sizeof(big_buffer));
                    if (size > 1024) {
                        memcpy(big_buffer, data, size);  // Potential overflow
                    }
                    return 32;
                }
                return 33;
                
            default:
                return 34;
        }
    }
    
    // Path 4: Process other inputs
    int sum = 0;
    for (size_t i = 0; i < size && i < 100; i++) {
        sum += data[i];
    }
    
    // Different paths based on checksum
    if (sum < 1000) {
        return 40;
    } else if (sum >= 1000 && sum < 5000) {
        return 41;
    } else if (sum >= 5000 && sum < 10000) {
        return 42;
    } else {
        return 43;
    }
}

// Slow function to simulate CPU-intensive processing
void slow_processing(int iterations) {
    volatile int sum = 0;
    for (int i = 0; i < iterations * 1000000; i++) {
        sum += i;
    }
}

int main(int argc, char *argv[]) {
    // Read input from file or stdin
    FILE *input = stdin;
    if (argc > 1) {
        input = fopen(argv[1], "rb");
        if (!input) {
            fprintf(stderr, "Error: Could not open input file %s\n", argv[1]);
            return 1;
        }
    }
    
    // Read input data
    uint8_t buffer[4096];
    size_t size = fread(buffer, 1, sizeof(buffer), input);
    
    if (input != stdin) {
        fclose(input);
    }
    
    // Process the data
    int result = process_data(buffer, size);
    
    // Simulate different processing times based on the path
    if (result > 0 && result < 10) {
        slow_processing(1);  // Path 1: Moderate processing
    } else if (result >= 10 && result < 20) {
        slow_processing(3);  // Path 1.1: Heavy processing
    } else if (result >= 20 && result < 30) {
        slow_processing(2);  // Path 2: Moderate-heavy processing
    } else if (result >= 30 && result < 40) {
        slow_processing(4);  // Path 3: Very heavy processing
    } else {
        slow_processing(1);  // Path 4: Moderate processing
    }
    
    printf("Result: %d\n", result);
    return 0;
}
