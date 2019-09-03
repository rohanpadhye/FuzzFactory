# FuzzFactory: Domain-Specific Fuzzing with Waypoints

FuzzFactory is an extension of [AFL](https://github.com/google/AFL) that generalizes coverage-guided fuzzing to domain-specific testing goals. FuzzFactory allows users to guide the fuzzer's search process without having to modify anything in AFL's search algorithm.

A paper on FuzzFactory has been [accepted to OOPSLA 2019](https://2019.splashcon.org/details/splash-2019-oopsla/57/FuzzFactory-Domain-Specific-Fuzzing-with-Waypoints). A replication package for the experimental evaluation described in the paper is available at: [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.3364086.svg)](https://doi.org/10.5281/zenodo.3364086).

## What are *Waypoints*?

FuzzFactory's key abstraction is that of waypoints. Waypoints are intermediate inputs that are saved during the fuzzing loop. These inputs need not increase code coverage, but they are saved because they make some sort of domain-specific progress. For example, PerfFuzz saves inputs that increase loop execution counts, a magic-byte fuzzer may save inputs that have partially correct magic bytes, or a directed fuzzer may save inputs that are more likely to exercise a program point of interest.

## How does FuzzFactory work?

FuzzFactory exposes an API (see `include/waypoints.h`) between the fuzzing algorithm and the test program. The test program can provide custom domain-specific feedback from test execution as key-value pairs, and specify how such feedback should be aggregated across multiple inputs. The aggregated feedback is used to decide if a given input should be considered a waypoint. The calls to the API can be injected either by modifying a test program by hand, or by inserting appropriate instrumentation in the test program. 


## Documentation and Examples



This section assumes some familiarity with AFL. 

To build FuzzFactory's custom `afl-fuzz`, run `make` in the root project directory.


### LLVM-based instrumentation

To build FuzzFactory's custom `afl-clang-fast`, run `make` in the `llvm` directory.

FuzzFactory provides an extension mechanism to quickly implement LLVM instrumentation passes that call into the FuzzFactory API; see `llvm_mode/fuzzfactory.hpp` and the following six domain implementations in `llvm_mode`:

- Domain `slow`:
  -  `waypoints-slow-pass.cc`: Implements domain `slow` described in Table 3 of the paper.
  -  `waypoints-slow-rt.c`: Allocates DSF map for `slow`.
- Domain `perf`:
  -  `waypoints-perf-pass.cc`: Implements domain `perf` described in Table 4 of the paper.
  -  `waypoints-perf-rt.c`: Allocates DSF map for `perf`.
- Domain `mem`:
  -  `waypoints-mem-pass.cc`: Implements domain `mem` described in Table 5 of the paper.
  -  `waypoints-mem-rt.c`: Allocates DSF map for `mem`.
- Domain `valid`:
  -  `waypoints-valid-pass.cc`: Implements domain `valid` described in Table 6 of the paper.
  -  `waypoints-valid-rt.c`: Allocates DSF map for `slow` and defines the logic for when the argument to `ASSUME()` is `false`.
- Domain `cmp`:
  -  `waypoints-cmp-pass.cc`: Implements domain `cmp` described in Table 7.
  -  `waypoints-cmp-rt.c`: Allocates DSF map for `cmp`, as well as defines all the `wrapcmp` functions that perform the common-bit-counting and update the DSF map accordingly. 
- Domain `diff`:
  -  `waypoints-diff-pass.cc`: Implements domain `diff` described in Table 7. 
  -  `waypoints-diff-rt.c`: Allocates globals used by domain `diff`.


### Fuzzing with FuzzFactory's LLVM-based domains


The directory `demo` contains a single-file test program (`demo.c`) to illustrate the use of FuzzFactory. Please switch to this directory for the remainder of this section.
```
cd demo
```

Background: This is how you would compile `demo.c` with regular AFL:

```
../afl/afl-clang-fast demo.c -o demo
```

This is how you would compile `demo.c` with FuzzFactory using the `mem` domain:
```
WAYPOINTS=mem ../fuzzfactory/afl-clang-fast demo.c -o demo
```

This is how you would compile `demo.c` with FuzzFactory using the `cmp` domain:
```
WAYPOINTS=cmp ../fuzzfactory/afl-clang-fast demo.c -o demo
```

This is how you would compile `demo.c` with FuzzFactory using the composition of the `cmp` and `mem` domain:
```
WAYPOINTS=cmp,mem ../fuzzfactory/afl-clang-fast demo.c -o demo
```

Now, let's fuzz the demo program using the seed file in the `seeds` subdirectory. The same command applies regardless of what domain was used to instrument the test program:

```
../fuzzfactory/afl-fuzz -p -i seeds -o results ./demo
```

If you fuzzed a program that has been instrumented with `cmp`+`mem` domains, you will see the following in the AFL output before fuzzing starts:
```
[+] 2 domain-specific front-end configs received
DSF 0: Start=0x000000, End=0x010000, Size=65536, Cumulator=1
DSF 1: Start=0x010000, End=0x010400, Size=1024, Cumulator=1
```

This is an indication that the test program has registered two domain-specific feedback maps with FuzzFactory.

The rest of the fuzzing session is similar to running [AFL as usual](http://lcamtuf.coredump.cx/afl). Press CTRL+C to stop fuzzing. During fuzzing, the following log file is created with verbose output about domain-specific feedback: `results/fuzzfactory.log`.

### New Domains via LLVM Instrumentation

To implement your own domain-specific instrumentation, let's call it domain `foo`, create files `waypoints-foo-pass.cc` and `waypoints-diff-rt.c`, and run `make` in the `llvm_mode` directory. Use the implementations listed above as templates. Once compiled, you can then instrument your test programs using the environment variable `WAYPOINTS=foo` when compiling with the `afl-clang-fast` built from this repo.

### New Domains via Manual API Invocation

*Documentation coming soon*



