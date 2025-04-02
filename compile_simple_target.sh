#!/bin/bash
# Compile simple_target with AFL instrumentation

# Determine the correct path to AFL tools
if [ -x "./afl-cc" ]; then
  AFL_PATH="."
elif [ -x "../afl-cc" ]; then
  AFL_PATH=".."
else
  echo "Error: Cannot find afl-cc. Make sure you're in the right directory."
  exit 1
fi

# Check if AFL_CC is set, otherwise use default CC
test -z "$AFL_CC" && AFL_CC="$AFL_PATH/afl-cc"
echo "Using compiler: $AFL_CC"

# Create simple_target.c if it doesn't exist
if [ ! -f "simple_target.c" ]; then
  echo "Creating simple_target.c..."
  cat > simple_target.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  FILE *f;
  char buf[100];
  
  if (argc < 2) {
    printf("Usage: %s <filename>\n", argv[0]);
    return 1;
  }
  
  f = fopen(argv[1], "r");
  if (!f) {
    perror("fopen");
    return 2;
  }
  
  size_t bytes_read = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[bytes_read] = '\0';
  
  // Add some branching logic to make it interesting for the fuzzer
  if (bytes_read > 0) {
    if (strncmp(buf, "FUZZCRSHY", 9) == 0) {
      // Simulate a crash for testing
      char *crash = NULL;
      *crash = 1;  // This will crash
    } else if (strncmp(buf, "FUZZ", 4) == 0) {
      printf("Found FUZZ prefix\n");
    } else {
      printf("No FUZZ prefix found\n");
    }
  }
  
  return 0;
}
EOF
fi

# Try different instrumentation methods
if [ -x "$AFL_PATH/afl-clang-fast" ]; then
  echo "Using afl-clang-fast for instrumentation"
  $AFL_PATH/afl-clang-fast -o simple_target simple_target.c || exit 1
elif [ -x "$AFL_PATH/afl-gcc" ]; then
  echo "Using afl-gcc for instrumentation"
  $AFL_PATH/afl-gcc -o simple_target simple_target.c || exit 1
else
  echo "Using generic afl-cc for instrumentation"
  $AFL_CC -o simple_target simple_target.c || exit 1
fi

echo "Target compilation successful"

# Verify that the binary is instrumented
echo "Verifying instrumentation..."
mkdir -p in
echo "FUZZTEST" > in/testcase

echo "Command: $AFL_PATH/afl-showmap -m none -o test-map.txt -- ./simple_target in/testcase"
$AFL_PATH/afl-showmap -m none -o test-map.txt -- ./simple_target in/testcase > test-showmap.log 2>&1
RESULT=$?
if [ $RESULT -ne 0 ]; then
  echo "Instrumentation verification failed with code $RESULT"
  echo "afl-showmap output:"
  cat test-showmap.log
  exit 1
fi
echo "Binary appears to be properly instrumented"

echo "You can now run the fuzzer with:"
echo "$AFL_PATH/afl-fuzz -i in -o out -m none -- ./simple_target @@"
