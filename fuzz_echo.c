/* fuzz_echo.c - Simplified version of echo for fuzzing
   Based on echo.c from GNU coreutils
   
   This is a simplified version of the echo utility from GNU coreutils,
   designed to be easily compiled for fuzzing purposes.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/* Convert C from hexadecimal character to integer. */
static int
hextobin(unsigned char c)
{
  switch (c)
    {
    default: return c - '0';
    case 'a': case 'A': return 10;
    case 'b': case 'B': return 11;
    case 'c': case 'C': return 12;
    case 'd': case 'D': return 13;
    case 'e': case 'E': return 14;
    case 'f': case 'F': return 15;
    }
}

/* Check if a character is a hexadecimal digit */
static bool
is_xdigit(unsigned char c)
{
  return (c >= '0' && c <= '9') || 
         (c >= 'a' && c <= 'f') || 
         (c >= 'A' && c <= 'F');
}

/* Process and echo the input string with escape sequence interpretation */
static void
process_string(const char *s, bool display_return)
{
  unsigned char c;

  while ((c = *s++))
    {
      if (c == '\\' && *s)
        {
          switch (c = *s++)
            {
            case 'a': c = '\a'; break;
            case 'b': c = '\b'; break;
            case 'c': return;
            case 'e': c = '\x1B'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'v': c = '\v'; break;
            case 'x':
              {
                unsigned char ch = *s;
                if (!is_xdigit(ch))
                  goto not_an_escape;
                s++;
                c = hextobin(ch);
                ch = *s;
                if (is_xdigit(ch))
                  {
                    s++;
                    c = c * 16 + hextobin(ch);
                  }
              }
              break;
            case '0':
              c = 0;
              if (!('0' <= *s && *s <= '7'))
                break;
              c = *s++;
              /* FALLTHROUGH */
            case '1': case '2': case '3':
            case '4': case '5': case '6': case '7':
              c -= '0';
              if ('0' <= *s && *s <= '7')
                c = c * 8 + (*s++ - '0');
              if ('0' <= *s && *s <= '7')
                c = c * 8 + (*s++ - '0');
              break;
            case '\\': break;

            not_an_escape:
            default:  putchar('\\'); break;
            }
        }
      putchar(c);
    }

  if (display_return)
    putchar('\n');
}

/* Main function for normal usage */
int
main(int argc, char **argv)
{
  bool display_return = true;
  bool do_interpret_escapes = false;
  int arg_index = 1;
  
  // Check if first argument is a file (for AFL++ compatibility)
  if (argc > 1 && argv[1][0] != '-') {
    // This is likely a filename from AFL++ (@@)
    FILE *f = fopen(argv[1], "r");
    if (f) {
      char buffer[4096];
      size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, f);
      buffer[bytes_read] = '\0';
      fclose(f);
      
      // Process the file contents
      process_string(buffer, display_return);
      return EXIT_SUCCESS;
    }
  }

  /* Process options */
  while (arg_index < argc && argv[arg_index][0] == '-')
    {
      const char *temp = argv[arg_index] + 1;
      size_t i;

      /* Check if all characters in the option are valid */
      for (i = 0; temp[i]; i++)
        {
          if (temp[i] != 'e' && temp[i] != 'E' && temp[i] != 'n')
            goto just_echo;
        }

      if (i == 0)
        goto just_echo;

      /* Process the options */
      while (*temp)
        {
          switch (*temp++)
            {
            case 'e':
              do_interpret_escapes = true;
              break;
            case 'E':
              do_interpret_escapes = false;
              break;
            case 'n':
              display_return = false;
              break;
            }
        }

      arg_index++;
    }

just_echo:
  
  if (do_interpret_escapes)
    {
      /* Process strings with escape interpretation */
      while (arg_index < argc)
        {
          process_string(argv[arg_index], false);
          arg_index++;
          if (arg_index < argc)
            putchar(' ');
        }
    }
  else
    {
      /* Simple echo without escape interpretation */
      while (arg_index < argc)
        {
          fputs(argv[arg_index], stdout);
          arg_index++;
          if (arg_index < argc)
            putchar(' ');
        }
    }

  if (display_return)
    putchar('\n');

  return EXIT_SUCCESS;
}

/* Fuzzing entry point - uncomment and use this when compiling with libFuzzer */
/*
int 
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) 
{
  if (size == 0)
    return 0;

  // Create a null-terminated string from the input data
  char *input = (char *)malloc(size + 1);
  if (!input)
    return 0;
  
  memcpy(input, data, size);
  input[size] = '\0';

  // Redirect stdout to /dev/null to avoid output during fuzzing
  FILE *devnull = fopen("/dev/null", "w");
  if (!devnull) {
    free(input);
    return 0;
  }
  
  FILE *old_stdout = stdout;
  stdout = devnull;

  // Process the input string with escape interpretation
  process_string(input, false);

  // Restore stdout and clean up
  stdout = old_stdout;
  fclose(devnull);
  free(input);

  return 0;
}
*/
