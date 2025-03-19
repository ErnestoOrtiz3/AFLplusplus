/*
 * Simple test program for eBPF file I/O optimization
 * This program reads input from a file and performs operations
 * that would benefit from eBPF file I/O optimizations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// Function to read file using standard file I/O
int process_file(const char *filename) {
  FILE *fp;
  char buffer[1024];
  size_t bytes_read;
  int result = 0;

  // Open the file
  fp = fopen(filename, "rb");
  if (!fp) {
    perror("Failed to open file");
    return -1;
  }

  // Read the file in chunks
  while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
    // Process the data
    for (size_t i = 0; i < bytes_read; i++) {
      // Simple processing to trigger different code paths
      if (buffer[i] == 'A') {
        result = 1;
      } else if (buffer[i] == 'B') {
        result = 2;
      } else if (buffer[i] == 'C') {
        result = 3;
      }
    }
  }

  // Close the file
  fclose(fp);
  return result;
}

// Alternative function using low-level file I/O
int process_file_lowlevel(const char *filename) {
  int fd;
  char buffer[1024];
  ssize_t bytes_read;
  int result = 0;

  // Open the file
  fd = open(filename, O_RDONLY);
  if (fd == -1) {
    perror("Failed to open file");
    return -1;
  }

  // Read the file in chunks
  while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
    // Process the data
    for (ssize_t i = 0; i < bytes_read; i++) {
      // Simple processing to trigger different code paths
      if (buffer[i] == 'X') {
        result = 4;
      } else if (buffer[i] == 'Y') {
        result = 5;
      } else if (buffer[i] == 'Z') {
        result = 6;
      }
    }
  }

  // Close the file
  close(fd);
  return result;
}

int main(int argc, char **argv) {
  int result1, result2;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
    return 1;
  }

  // Process the file using both methods
  result1 = process_file(argv[1]);
  result2 = process_file_lowlevel(argv[1]);

  // Crash on specific input to verify fuzzer functionality
  if (result1 == 1 && result2 == 4) {
    fprintf(stderr, "Found interesting input!\n");
    abort(); // Crash to demonstrate fuzzer finding bugs
  }

  return 0;
}