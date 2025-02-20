#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Function with predictable branch behavior
int process_input(const char* input, size_t len) {
    int count = 0;
    
    // Branch 1: Length-dependent behavior
    if (len > 10) {
        for (int i = 0; i < 100000; i++) {
            count += i % 2;  // Predictable branch
        }
    }
    
    // Branch 2: Content-dependent behavior
    if (len > 0 && input[0] == 'A') {
        for (int i = 0; i < 50000; i++) {
            count += i % 3;  // Different branch pattern
        }
    }
    
    // Branch 3: Pattern matching
    if (len > 4 && memcmp(input, "FUZZ", 4) == 0) {
        for (int i = 0; i < 75000; i++) {
            count += i % 4;  // Another branch pattern
        }
    }
    
    return count;
}

int main(int argc, char** argv) {
    char buffer[1024];
    ssize_t len = read(0, buffer, sizeof(buffer) - 1);
    
    if (len <= 0) return 1;
    
    buffer[len] = '\0';
    int result = process_input(buffer, len);
    
    // Use result to prevent optimization
    return (result & 0xFF) == 0;
}