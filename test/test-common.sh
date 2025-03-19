#!/bin/sh

# Common definitions for test scripts

# Colors
RESET="\033[0m"
GREY="\033[1;90m"
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
MAGENTA="\033[1;35m"
CYAN="\033[1;36m"
WHITE="\033[1;37m"

# Command for echo with escape sequences
ECHO="printf %b\\n"
$ECHO \\101 2>/dev/null | grep -qE '^A' || {
  ECHO=
  test -e /bin/printf && {
    ECHO="/bin/printf %b\\n"
    $ECHO '\\101' 2>/dev/null | grep -qE '^A' || ECHO=
  }
}
test -z "$ECHO" && ECHO="echo"

# Default compiler
CC=${CC:-gcc}

# Memory limit for tests
MEM_LIMIT=none

# Check for GNU make
MAKE=make
gmake --version >/dev/null 2>&1 && MAKE=gmake

# Temporary directory
TESTDIR="$(pwd)/test-tmp"