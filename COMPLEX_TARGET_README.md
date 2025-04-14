# Complex Fuzzing Target for AFL++ Scheduler Testing

This project provides a sophisticated fuzzing target designed to test the effectiveness of a custom CPU scheduler for the AFL++ fuzzing tool. The target simulates a multimedia file parser with multiple components and varying computational complexity.

## Components

The complex target consists of the following components:

1. **File Format Parser**: Handles header validation, metadata extraction, and content parsing with multiple formats.
2. **Image Processing Module**: Implements different compression algorithms, various filters, and transformations.
3. **Audio Processing Module**: Handles sample rate conversion, effects processing, and format decoding.
4. **Text Processing Module**: Processes markup language, templates, and performs text analysis.
5. **Mixed Content Module**: Combines multiple content types in a single file.

## Features

- **Multiple Content Types**: Supports image, audio, text, and mixed content types.
- **Varying Computational Complexity**: Different processing algorithms have different CPU requirements.
- **Hidden Bugs**: Contains various types of vulnerabilities that are challenging to find.
- **Complex Code Paths**: Multiple execution paths that require different types of inputs.
- **State Dependencies**: Some bugs only appear when specific sequences of operations are performed.

## Files

- `complex_target.c`: The main target implementation.
- `generate_test_input.c`: Utility to generate valid test inputs for the target.
- `fuzz_complex_target.sh`: Script to instrument the target with AFL++ and start fuzzing.

## Building

To build the target and test input generator:

```bash
gcc -o complex_target complex_target.c -lm
gcc -o generate_test_input generate_test_input.c
```

## Generating Test Inputs

Run the test input generator to create initial seed files:

```bash
./generate_test_input
```

This will create 10 different test files in the current directory, covering different content types and processing flags.

## Fuzzing with AFL++

To instrument the target with AFL++ and start fuzzing:

```bash
./fuzz_complex_target.sh
```

This script will:
1. Compile the target with AFL++ instrumentation
2. Start the AFL++ fuzzer using the generated test inputs as seeds

## Testing the AFL++ Scheduler

To test the effectiveness of the AFL++ CPU scheduler:

1. Run multiple instances of AFL++ with the custom scheduler enabled
2. Run the same number of instances with the standard Linux CFS scheduler
3. Compare the results to see which scheduler produces better fuzzing outcomes

The target is designed to benefit from the custom scheduler by having:
- Paths with varying computational complexity
- Dependencies between different code paths
- Bugs that require specific sequences of operations to trigger

## Vulnerabilities

The target contains various types of vulnerabilities, including:

- Buffer overflows
- Null pointer dereferences
- Use-after-free issues
- Integer overflows
- Off-by-one errors
- Memory leaks
- Logic bugs

These vulnerabilities are hidden in different parts of the code and require specific inputs to trigger.

## License

This project is provided for educational and testing purposes only.
