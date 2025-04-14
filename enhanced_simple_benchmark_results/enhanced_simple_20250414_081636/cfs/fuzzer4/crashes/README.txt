Command line used to find this crash:

/home/ernesto/Documents/AFLplusplus/afl-fuzz -i /home/ernesto/Documents/AFLplusplus/original_seeds -o enhanced_simple_benchmark_results/enhanced_simple_20250414_081636/cfs -S fuzzer4 -t 7500+ -m none -- ./complex_target_afl @@

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please post
to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the issues
 are fixed :)

