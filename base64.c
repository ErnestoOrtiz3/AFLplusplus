/* base64 - simplified version for fuzzing
   Based on GNU coreutils base64, but simplified and with intentional bugs
   
   This is a standalone version with no external dependencies
   for use in fuzzing campaigns.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#define PROGRAM_NAME "base64"

/* Buffer sizes */
#define ENC_BLOCKSIZE (1024 * 16)
#define DEC_BLOCKSIZE (1024 * 3)

/* BUG 1: Buffer overflow vulnerability - undersized buffer for filenames */
#define MAX_FILENAME 20
static char current_filename[MAX_FILENAME];

/* Base64 encoding table */
static const char base64_chars[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* BUG 2: Incorrect decoding table - some values are wrong */
static const signed char base64_decode_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

/* BUG 3: Use-after-free vulnerability */
static char *dynamic_buffer = NULL;

/* BUG 4: Integer overflow vulnerability in length calculation */
static size_t base64_length(size_t inlen) {
    // Intentionally vulnerable to integer overflow
    return ((inlen + 2) / 3) * 4;
}

/* Check if a character is a valid base64 character */
static bool is_base64(unsigned char c) {
    return c < 256 && base64_decode_table[c] >= 0;
}

/* BUG 5: Off-by-one error in buffer handling */
static void process_buffer(char *buf, size_t size) {
    // Intentional off-by-one error
    for (size_t i = 0; i <= size; i++) {  // Should be i < size
        if (buf[i] == '\n') {
            // Do something with newlines
            buf[i] = ' ';
        }
    }
}

/* Base64 encode a block of data */
static void base64_encode_block(const char *in, size_t inlen, char *out, size_t outlen) {
    size_t i, j;
    unsigned char a, b, c;
    
    // BUG 6: Memory leak - allocate but never free in some cases
    if (rand() % 10 == 0) {
        dynamic_buffer = malloc(1024);
        // No free() for this allocation
    }
    
    for (i = 0, j = 0; i < inlen && j < outlen; ) {
        a = i < inlen ? (unsigned char)in[i++] : 0;
        b = i < inlen ? (unsigned char)in[i++] : 0;
        c = i < inlen ? (unsigned char)in[i++] : 0;
        
        if (j < outlen) out[j++] = base64_chars[(a >> 2) & 0x3F];
        if (j < outlen) out[j++] = base64_chars[((a & 0x03) << 4) | ((b >> 4) & 0x0F)];
        if (j < outlen) out[j++] = i > inlen + 1 ? '=' : base64_chars[((b & 0x0F) << 2) | ((c >> 6) & 0x03)];
        if (j < outlen) out[j++] = i > inlen ? '=' : base64_chars[c & 0x3F];
    }
    
    // BUG 7: Potential buffer overflow if outlen is not checked properly
    if (j < outlen) {
        out[j] = '\0';
    }
}

/* Base64 decode a block of data */
static bool base64_decode_block(const char *in, size_t inlen, char *out, size_t *outlen) {
    size_t i, j;
    unsigned char a, b, c, d;
    
    // BUG 8: Null pointer dereference possibility
    if (inlen > DEC_BLOCKSIZE * 2 && (rand() % 100) == 42) {
        out = NULL;
    }
    
    for (i = 0, j = 0; i < inlen && j < *outlen; ) {
        // Skip whitespace and other non-base64 chars
        while (i < inlen && !is_base64((unsigned char)in[i]) && in[i] != '=') {
            i++;
        }
        
        if (i >= inlen || in[i] == '=') break;
        
        // BUG 9: Incorrect bounds checking
        a = base64_decode_table[(unsigned char)in[i++]];
        if (i >= inlen) break;
        b = base64_decode_table[(unsigned char)in[i++]];
        if (i >= inlen) break;
        c = i < inlen && in[i] != '=' ? base64_decode_table[(unsigned char)in[i++]] : 0;
        if (i >= inlen) break;
        d = i < inlen && in[i] != '=' ? base64_decode_table[(unsigned char)in[i++]] : 0;
        
        // BUG 10: Potential buffer overflow in output
        out[j++] = (a << 2) | (b >> 4);
        if (in[i-2] != '=') out[j++] = (b << 4) | (c >> 2);
        if (in[i-1] != '=') out[j++] = (c << 6) | d;
    }
    
    *outlen = j;
    return true;
}

/* Complex function with potential division by zero */
static void complex_calculation(size_t bytes_read) {
    static int divisor = 1;
    static int counter = 0;
    
    // BUG 11: Potential division by zero
    if (bytes_read % 17 == 0) {
        divisor--;
    } else if (bytes_read % 23 == 0) {
        divisor++;
    }
    
    if (counter++ % 50 == 0) {
        // This will crash with division by zero when divisor becomes 0
        int result = bytes_read / divisor;
        if (result > 1000) {
            printf("Complex result: %d\n", result);
        }
    }
}

/* Encode data from input file to output file */
static int encode_file(FILE *in, FILE *out) {
    char *inbuf, *outbuf;
    size_t inbufsize, outbufsize, bytes_read, total_read;
    
    inbufsize = ENC_BLOCKSIZE;
    outbufsize = base64_length(inbufsize);
    
    inbuf = malloc(inbufsize);
    if (!inbuf) {
        perror("malloc");
        return 1;
    }
    
    outbuf = malloc(outbufsize + 1);  // +1 for null terminator
    if (!outbuf) {
        perror("malloc");
        free(inbuf);
        return 1;
    }
    
    while (!feof(in)) {
        total_read = 0;
        
        while (total_read < inbufsize && !feof(in)) {
            bytes_read = fread(inbuf + total_read, 1, inbufsize - total_read, in);
            if (ferror(in)) {
                perror("fread");
                free(inbuf);
                free(outbuf);
                return 1;
            }
            total_read += bytes_read;
        }
        
        if (total_read > 0) {
            // BUG 12: Call complex function that might crash
            complex_calculation(total_read);
            
            base64_encode_block(inbuf, total_read, outbuf, outbufsize);
            
            // BUG 13: Call function with off-by-one error
            process_buffer(outbuf, strlen(outbuf));
            
            if (fputs(outbuf, out) == EOF) {
                perror("fputs");
                free(inbuf);
                free(outbuf);
                return 1;
            }
            
            // Add a newline every 76 characters
            if (fputs("\n", out) == EOF) {
                perror("fputs");
                free(inbuf);
                free(outbuf);
                return 1;
            }
        }
    }
    
    free(inbuf);
    free(outbuf);
    return 0;
}

/* Decode data from input file to output file */
static int decode_file(FILE *in, FILE *out) {
    char *inbuf, *outbuf;
    size_t inbufsize, outbufsize, bytes_read, total_read, outlen;
    
    inbufsize = DEC_BLOCKSIZE;
    outbufsize = (inbufsize / 4) * 3;  // Maximum possible decoded size
    
    inbuf = malloc(inbufsize);
    if (!inbuf) {
        perror("malloc");
        return 1;
    }
    
    outbuf = malloc(outbufsize);
    if (!outbuf) {
        perror("malloc");
        free(inbuf);
        return 1;
    }
    
    while (!feof(in)) {
        total_read = 0;
        
        while (total_read < inbufsize && !feof(in)) {
            bytes_read = fread(inbuf + total_read, 1, inbufsize - total_read, in);
            if (ferror(in)) {
                perror("fread");
                free(inbuf);
                free(outbuf);
                return 1;
            }
            total_read += bytes_read;
        }
        
        if (total_read > 0) {
            outlen = outbufsize;
            if (base64_decode_block(inbuf, total_read, outbuf, &outlen)) {
                if (fwrite(outbuf, 1, outlen, out) != outlen) {
                    perror("fwrite");
                    free(inbuf);
                    free(outbuf);
                    return 1;
                }
            }
        }
    }
    
    free(inbuf);
    free(outbuf);
    return 0;
}

int main(int argc, char **argv) {
    int status = 0;
    bool decode_mode = false;
    FILE *input = stdin;
    FILE *output = stdout;
    
    // Initialize random seed for our "random" bugs
    srand(42);
    
    // If no arguments, read from stdin and write to stdout
    if (argc == 1) {
        strncpy(current_filename, "stdin", MAX_FILENAME - 1);
        current_filename[MAX_FILENAME - 1] = '\0';  // Ensure null termination
        
        if (encode_file(input, output) != 0) {
            status = 1;
        }
    } else {
        // Simple argument parsing - only support -d for decode and filenames
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-d") == 0) {
                decode_mode = true;
            } else {
                // BUG 14: Buffer overflow in filename copy
                strcpy(current_filename, argv[i]);  // No bounds checking
                
                input = fopen(argv[i], "r");
                if (!input) {
                    fprintf(stderr, "%s: %s: %s\n", PROGRAM_NAME, argv[i], strerror(errno));
                    status = 1;
                    continue;
                }
                
                if (decode_mode) {
                    if (decode_file(input, output) != 0) {
                        status = 1;
                    }
                } else {
                    if (encode_file(input, output) != 0) {
                        status = 1;
                    }
                }
                
                fclose(input);
            }
        }
    }
    
    // BUG 15: Use-after-free
    if (dynamic_buffer) {
        free(dynamic_buffer);
        // Intentional use-after-free
        if (dynamic_buffer[0] == 'A') {
            printf("Found an 'A'!\n");
        }
    }
    
    return status;
}
