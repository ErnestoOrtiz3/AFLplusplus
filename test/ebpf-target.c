#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char buf[256];
    FILE *f;
    
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    f = fopen(argv[1], "r");
    if (!f) return 1;
    
    if (fgets(buf, sizeof(buf), f) == NULL) {
        fclose(f);
        return 1;
    }
    fclose(f);
    
    // Based on input, execute different commands
    switch(buf[0]) {
        case '1':
            system("ls");
            break;
        case '2':
            system("pwd");
            break;
        case '3':
            execl("/bin/echo", "echo", "hello", NULL);
            break;
        default:
            printf("Invalid input\n");
    }
    
    return 0;
}
