# FuzzFactory: Domain-Specific Fuzzing with Waypoints

![FuzzFactory logo](https://github.com/rohanpadhye/FuzzFactory/blob/master/img/logo_small.png)

FuzzFactory is an extension of [AFL](https://github.com/google/AFL) that generalizes coverage-guided fuzzing to domain-specific testing goals. FuzzFactory allows users to guide the fuzzer's search process without having to modify anything in AFL's search algorithm.

A paper on FuzzFactory has been [accepted to OOPSLA 2019](https://2019.splashcon.org/details/splash-2019-oopsla/57/FuzzFactory-Domain-Specific-Fuzzing-with-Waypoints). FuzzFactory has been developed by [Rohan Padhye](https://cs.berkeley.edu/~rohanpadhye) and [Caroline Lemieux](https://www.carolemieux.com).
A replication package for the experimental evaluation described in the paper is [available on Zenodo](https://doi.org/10.5281/zenodo.3364086).

## What are *Waypoints*?

FuzzFactory's key abstraction is that of *waypoints*: intermediate inputs that are saved during the fuzzing loop. These inputs need not increase code coverage, but they are saved because they make some sort of domain-specific progress. For example, PerfFuzz saves inputs that increase loop execution counts, a magic-byte fuzzer may save inputs that have partially correct magic bytes, or a directed fuzzer may save inputs that are more likely to exercise a program point of interest.

## How does FuzzFactory work?

FuzzFactory exposes an API (see `include/waypoints.h`) between the fuzzing algorithm and the test program. The test program can provide custom domain-specific feedback from test execution as key-value pairs, and specify how such feedback should be aggregated across multiple inputs by choosing a *reducer function*. The aggregated feedback is used to decide if a given input should be considered a waypoint. The calls to the API can be injected either by modifying a test program by hand, or by inserting appropriate instrumentation in the test program. 


## Documentation and Examples

This section assumes some familiarity with AFL. 

To build FuzzFactory's custom `afl-fuzz`, run `make` in the root project directory. 

You can use this `afl-fuzz` to fuzz regular AFL-instrumented programs as before.

You can also use this `afl-fuzz` with the `-p` option to enable fuzzing programs that are instrumented (option 1) or modified (option 2) to call into FuzzFactory's API.


### Option 1: Domain-Specific Feedback via LLVM-based instrumentation

To build FuzzFactory's LLVM-based domain-specific instrumentation, run `make llvm-domains` in the root project directory; you will need LLVM/Clang 6+ installed (AFL needs to find `llvm_config`). This will build a special version of `afl-clang-fast` that supports domain-specific instrumentation passes as plugins. This command also builds six domain-specific instrumentation passes that ship with FuzzFactory; these correspond to the six domains listed in the paper: `slow`, `perf`, `mem`, `valid`, `cmp`, `diff`.

FuzzFactory provides an extension mechanism to quickly implement LLVM instrumentation passes that call into the FuzzFactory API; see `llvm_mode/fuzzfactory.hpp` and the following six domain implementations in `llvm_mode`:

- Domain `slow` (inspired by [SlowFuzz](https://doi.org/10.1145/3133956.3134073)):
  -  `waypoints-slow-pass.cc`: Implements domain `slow` described in Table 3 of the paper.
  -  `waypoints-slow-rt.c`: Allocates DSF map for `slow`.
- Domain `perf` (port of [PerfFuzz](https://doi.org/10.1145/3213846.3213874)):
  -  `waypoints-perf-pass.cc`: Implements domain `perf` described in Table 4 of the paper.
  -  `waypoints-perf-rt.c`: Allocates DSF map for `perf`.
- Domain `mem` (malloc/calloc fuzzer):
  -  `waypoints-mem-pass.cc`: Implements domain `mem` described in Table 5 of the paper.
  -  `waypoints-mem-rt.c`: Allocates DSF map for `mem`.
- Domain `valid` (port of [Zest-v](https://doi.org/10.1109/ICSE-Companion.2019.00107)):
  -  `waypoints-valid-pass.cc`: Implements domain `valid` described in Table 6 of the paper.
  -  `waypoints-valid-rt.c`: Allocates DSF map for `slow` and defines the logic for when the argument to `ASSUME()` is `false`.
- Domain `cmp` (magic-byte and checksum fuzzer):
  -  `waypoints-cmp-pass.cc`: Implements domain `cmp` described in Table 7 in the paper.
  -  `waypoints-cmp-rt.c`: Allocates DSF map for `cmp`, as well as defines all the `wrapcmp` functions that perform the common-bit-counting and update the DSF map accordingly. 
- Domain `diff` (incremental fuzzer):
  -  `waypoints-diff-pass.cc`: Implements domain `diff` described in Table 8 in the paper. 
  -  `waypoints-diff-rt.c`: Allocates globals used by domain `diff`.


#### Fuzzing with FuzzFactory's LLVM-based domains

This section assumes you have LLVM/Clang installed and have run `make llvm-domains` in the root directory.

The directory `demo` contains a single-file test program (`demo.c`) to illustrate the use of FuzzFactory. Please switch to this directory for the remainder of this section.
```
cd demo
```

Background: This is how you would compile `demo.c` with regular AFL:

```
../afl-clang-fast demo.c -o demo
```

This is how you would compile `demo.c` with FuzzFactory using the `mem` domain:
```
WAYPOINTS=mem ../afl-clang-fast demo.c -o demo
```

This is how you would compile `demo.c` with FuzzFactory using the `cmp` domain:
```
WAYPOINTS=cmp ../afl-clang-fast demo.c -o demo
```

This is how you would compile `demo.c` with FuzzFactory using the composition of the `cmp` and `mem` domain:
```
WAYPOINTS=cmp,mem ../afl-clang-fast demo.c -o demo
```

Now, let's fuzz the demo program using the seed file in the `seeds` subdirectory. The same command applies regardless of what domain was used to instrument the test program:

```
../afl-fuzz -p -i seeds -o results ./demo
```

If you fuzzed a program that has been instrumented with `cmp`+`mem` domains, you will see the following in the AFL output before fuzzing starts:
```
[+] 2 domain-specific front-end configs received
DSF 0: Start=0x000000, End=0x010000, Size=65536, Cumulator=1
DSF 1: Start=0x010000, End=0x010400, Size=1024, Cumulator=1
```

This is an indication that the test program has registered two domain-specific feedback maps with FuzzFactory.

The rest of the fuzzing session is similar to running [AFL as usual](http://lcamtuf.coredump.cx/afl). Press CTRL+C to stop fuzzing. During fuzzing, the following log file is created with verbose output about domain-specific feedback: `results/fuzzfactory.log`.

#### New Domains via LLVM Instrumentation

To implement your own domain-specific instrumentation pass, let's call it domain `foo`: (1) create files `waypoints-foo-pass.cc` and `waypoints-foo-rt.c` in the `llvm_mode` directory, (2) run `make llvm-domains DOMAINS+=foo` in the root directory, (3) compile your test programs with `afl-clang-fast` after setting the environment var `WAYPOINTS=foo`. For help in creating the pass and runtime files, use the implementations listed in the previous section as templates. 

### Option 2: Domain-Specific Feedback via Manual API Invocation

FuzzFactory can also be used to manually augment a test program and specify domain-specific testing goals. Simply include `waypoints.h` and use the following macros from your test program:

```
/** 
 * Creates a new DSF map `name` with `size` keys, `reducer` function, and `initial` aggregate value.
 *
 * To be called at the top-level global scope.
 */
FUZZFACTORY_DSF_NEW(name, size, reducer, initial)

/** Set dsf[k] = max(dsf[k], v); */
FUZZFACTORY_DSF_MAX(dsf, k, v)

/** Set dsf[k] = dsf[k] | v; */
FUZZFACTORY_DSF_BIT(dsf, k, v)

/** Set dsf[k] = v; */
FUZZFACTORY_DSF_SET(dsf, k, v)

/** Set dsf[k] = dsf[k] + v; */
FUZZFACTORY_DSF_INC(dsf, k, v)
```

#### Demo with Clang

This section assumes you have LLVM/Clang installed and have run `make llvm-domains` in the root directory.

To see a sample usage of these macros from a test program, cd to the `demo` directory and run the following:

```
diff demo.c demo-manual.c    # Compare demo program with fuzzfactory-macro augmented test program
```

Compile the augmented test program as follows:

```
../afl-clang-fast demo-manual.c -o demo-manual
```

Fuzz the augmented test program using the `-p` option to enable domain-specific fuzzing:

```
../afl-fuzz -p -i seeds/ -o results ./demo-manual
```

Fuzzing the augmented program will be similar to fuzzing the original demo program with waypoints `cmp` and `mem` enabled. Again, you will see output like:

```
[+] 1 domain-specific front-end configs received
DSF 0: Start=0x000000, End=0x010000, Size=4, Cumulator=1
```
and the start of the AFL status screen. 

### Analzying domain-specific info from saved inputs

Apart from finding crashes (bugs), we are also often interested in generating inputs that optimize some domain-specific metric. For example, after fuzzing with the `perf` domain, which is an instantiation of [PerfFuzz](https://github.com/carolemieux/perffuzz) in FuzzFactory, we would like to find the maximum loop count across all saved inputs. Either for this purpose, or simply for debugging your domain-specific instrumentation, FuzzFactory provides a utility tool called `afl-showdsf` that analyzes domain-specific feedback from one or more saved inputs.

Run `./afl-showdsf` without any arguments to see its usage. 

**Replaying Single Input**: Run `afl-showdsf` followed by the command for running the test program along with its input, to see DSF from a single execution. From the `demo` directory referenced in the previous sections, run:
```
../afl-showdsf ./demo < seeds/zerozero.txt 
```

**Aggregation Across Inputs**: Run `afl-showdsf` with `-i <dir>` to execute all inputs in a directory and aggregate their domain-specific feedback using the reducer function that is registered with each domain (e.g. `MAX` for domain `perf`). From the `demo` directory, after fuzzing with `-p` for a while, run:
```
../afl-showdsf -i results/queue/ -- ./demo
```

