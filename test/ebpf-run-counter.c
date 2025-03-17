/*
 * Simple test program for eBPF counter performance testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char **argv) {
  
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
    return 1;
  }
  
  // Read input file
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 2;
  }
  
  char buf[16];
  ssize_t n_read = read(fd, buf, sizeof(buf) - 1);
  if (n_read <= 0) {
    perror("read");
    close(fd);
    return 3;
  }
  
  buf[n_read] = '\0';
  close(fd);
  
  // Simple processing to ensure the compiler doesn't optimize away our code
  int result = 0;
  for (int i = 0; i < n_read; i++) {
    if (buf[i] == '0') result += 1;
    else if (buf[i] == '1') result += 2;
    else if (buf[i] == '2') result += 3;
    else if (buf[i] == '3') result += 4;
    else if (buf[i] == 'x') {
      // Simulate a crash for testing
      if (getenv("AFL_CRASH_TEST")) {
        abort();
      }
    }
  }
  
  return result & 0xff;
}
