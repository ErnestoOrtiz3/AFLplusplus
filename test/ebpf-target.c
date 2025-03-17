#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char buf[10] = {0};
    FILE *fp;
    
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("Failed to open input file");
        return 1;
    }
    
    // Read first byte from input
    if (fread(buf, 1, 1, fp) < 1) {
        printf("Failed to read input\n");
        fclose(fp);
        return 1;
    }
    
    fclose(fp);
    
    // Based on input, execute different code paths
    switch(buf[0]) {
        case '1':
            printf("Would have run: ls\n");
            // For a real test, you could use: system("ls");
            break;
        case '2':
            printf("Would have run: pwd\n");
            // For a real test, you could use: system("pwd");
            break;
        case '3':
            printf("hello\n");
            break;
        default:
            printf("Invalid input: %c\n", buf[0]);
    }
    
    return 0;
}
