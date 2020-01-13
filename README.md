# FuzzFactory: Domain-Specific Fuzzing with Waypoints

![FuzzFactory logo](https://github.com/rohanpadhye/FuzzFactory/blob/master/img/logo_small.png)

FuzzFactory is an extension of [AFL](https://github.com/google/AFL) that generalizes coverage-guided fuzzing to domain-specific testing goals. FuzzFactory allows users to guide the fuzzer's search process without having to modify anything in AFL's search algorithm.

Most details are described in the following research paper:

> Rohan Padhye, Caroline Lemieux, Koushik Sen, Laurent Simon, and Hayawardh Vijayakumar. 2019. FuzzFactory: Domain-Specific Fuzzing with Waypoints. Proc. ACM Program. Lang. 3, OOPSLA, Article 174 (October 2019), 29 pages. https://doi.org/10.1145/3360600

A replication package for the experimental evaluation described in the paper is [available on Zenodo](https://doi.org/10.5281/zenodo.3364086).

## What are *Waypoints*?

FuzzFactory's key abstraction is that of *waypoints*: intermediate inputs that are saved during the fuzzing loop. These inputs need not increase code coverage, but they are saved because they make some sort of domain-specific progress. For example, PerfFuzz saves inputs that increase loop execution counts, a magic-byte fuzzer may save inputs that have partially correct magic bytes, or a directed fuzzer may save inputs that are more likely to exercise a program point of interest.

## How does FuzzFactory work?

FuzzFactory exposes an API (see `include/waypoints.h`) between the fuzzing algorithm and the test program. The test program can provide custom domain-specific feedback from test execution as *key-value pairs*, and specify how such feedback should be aggregated across multiple inputs by choosing a *reducer function*. The aggregated feedback is used to decide if a given input should be considered a waypoint. The calls to the API can be injected either by modifying a test program by hand, or by inserting appropriate instrumentation in the test program at compile-time. 

## Why is FuzzFactory useful?

Here is a cool example of something the authors did with FuzzFactory:
1. Built `mem`, a fuzzer that generates inputs that maximize arguments to `malloc()` in **29 lines of code**.
2. Built `cmp`, a fuzzer that surpasses variable-sized magic values, checksums, and other comparisons across integers, strings, and byte buffers, in **355 lines of code**.
3. Composed `cmp`+`mem`, to build a super-fuzzer called `cmp-mem` that surpasses comparisons while simultaneously maximizing mallocs, using **a single command-line flag**.
4. Used `cmp-mem` to find **two new bugs** in `libarchive` [[#1165](https://github.com/libarchive/libarchive/issues/1165), [#1237](https://github.com/libarchive/libarchive/issues/1237)]. Also [replicated a known allocation bug in libpng](https://github.com/google/fuzzer-test-suite/tree/b2e885706d63957a027ad98f46fbc281ffb2af9b/libpng-1.2.56), *without using any seed inputs*.

The super-fuzzer (`cmp-mem`) outperforms not only AFL, but also its constituents `cmp` and `mem`, on finding these memory allocation issues:

<p align="center">
<img alt="Evaluation of FuzzFactory's cmp-mem composition" src="https://github.com/rohanpadhye/FuzzFactory/blob/master/img/eval_cmp-mem.png" height="400" />
</p>

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
DSF 0: Start=0x000000, End=0x010000, Size=65536, Reducer[0]=MAX, Initial=0
DSF 1: Start=0x010000, End=0x010400, Size=1024, Reducer[0]=MAX, Initial=0
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
DSF 0: Start=0x000000, End=0x000004, Size=4, Reducer[0]=0x55a947da28f0, Initial=0
```
and the start of the AFL status screen. 

### Analzying domain-specific info from saved inputs

Apart from finding crashes (bugs), we are also often interested in generating inputs that optimize some domain-specific metric. For example, after fuzzing with the `perf` domain, which is an instantiation of [PerfFuzz](https://github.com/carolemieux/perffuzz) in FuzzFactory, we would like to find the maximum loop count across all saved inputs. Either for this purpose, or simply for debugging your domain-specific instrumentation, FuzzFactory provides a utility tool called `afl-showdsf` that analyzes domain-specific feedback from one or more saved inputs.

Run `afl-showdsf` without any arguments to see its usage. 

**Replaying Single Input**: Run `afl-showdsf` followed by the command for running the test program along with its input, to see DSF from a single execution. From the `demo` directory referenced in the previous sections, run:
```
../afl-showdsf ./demo-manual < seeds/zerozero.txt 
```

This will output a similar header to FuzzFactory's `afl-fuzz`, followed by the output from running the test program on the input itself:
```
[+] 1 domain-specific front-end configs received
DSF 0: Start=0x000000, End=0x000004, Size=4, Reducer[0]=MAX, Initial=0
Total DSF map length = 4
170920496, 0
Demo: Reached point A
Demo: Reached point B
```

This output will be followed by list of lines of the form:
```
dsf[k] = v
```
indicating that during execution, the input triggered the domain specific feedback value `v` for key `k`. Only the keys `k` for which `v` is not the initial aggregation value will be shown. 

In the above example, we will see a single line:
```
dsf[0] = 19

```
which tells us that the comparison at key `0` had `19` bits common between the operands (see [`demo-manual.c`](https://github.com/rohanpadhye/FuzzFactory/blob/master/demo/demo-manual.c#L29)) when running the seed input.

**Aggregation Across Inputs**: Run `afl-showdsf` with `-i <dir>` to execute all inputs in a directory and aggregate their domain-specific feedback using the reducer function that is registered with each domain (e.g. `MAX` for domain `perf`). From the `demo` directory, after fuzzing `demo-manual` with `-p` for a while, run:
```
../afl-showdsf -i results/queue/ -- ./demo-manual
```
Again, this will output a similar header to regular `afl-fuzz`, along with a list of lines of the form:
```
dsf[k] = v
```
This time, each entry represents an aggregate over all inputs in the directory. For each key `k` in the domain-specific feedback map, the corresponding aggregated feedback value seen is `v`. Only the keys `k` for which `v` is not the initial aggregation value will be shown.

```
Receiving 1 domain-specific front-ends..
[+] 1 domain-specific front-end configs received
DSF 0: Start=0x000000, End=0x000004, Size=4, Reducer[0]=MAX, Initial=0
Total DSF map length = 4
dsf[0] = 32
dsf[1] = 27
dsf[2] = 2147483645
```
The entry for key `0` tells us that there was at least one input which matched all `32` bits of the [first comparison in demo-manual.c](https://github.com/rohanpadhye/FuzzFactory/blob/master/demo/demo-manual.c#L29), while the entry for key `2` tells us that the [most amount of memory allocated at demo-manual.c](https://github.com/rohanpadhye/FuzzFactory/blob/master/demo/demo-manual.c#L45) is `2147483645` bytes.

**Interpreting Results for Composed DSF**: When running `afl-showdsf` with a program instrumented with composed dsf, e.g. the `WAYPOINTS=cmp,mem` example above with program `demo`, we can separate out the dsf values for different domains based on the header output. For example, after running:
```
../afl-showdsf -i results/queue/ -- ./demo
```
we will see output like:
```
DSF 0: Start=0x000000, End=0x010000, Size=65536, Reducer[0]=MAX, Initial=0
DSF 1: Start=0x010000, End=0x010400, Size=1024, Reducer[0]=MAX, Initial=0
Total DSF map length = 66560
dsf[7109] = 32
dsf[21658] = 32
dsf[33477] = 27
dsf[65690] = 2147483645
```
We see two dsf values: `dsf[7109] = 30` and `dsf[21658] = 32`. One question that we might want to ask is whether these values are from the `cmp` or the `mem` domain. 

The information in the header helps us distinguish the domains:
```
DSF 0: Start=0x000000, End=0x010000, Size=65536, Reducer[0]=MAX, Initial=0
```
says that all keys from `0x000000` to `0x010000`, exclusive of the last key (i.e. \[0, 65536)), belong to the first domain (cmp). The second line,
```
DSF 1: Start=0x010000, End=0x010400, Size=1024, Reducer[0]=MAX, Initial=0
```
says that all keys from `0x010000` to `0x010400`, exclusive of the last key (i.e. \[65536, 66560)), belong to the second dsf (mem).

Thus, the two printed values `dsf[7109] = 32` and `dsf[21658] = 32` both belong to the `cmp` domain, and show that these comparison were surpassed. The value `dsf[65690] = 2147483645` shows an entry from the `mem` domain (since the key is in the range \[65536, 66560)), and indicates that the max memory allocation at some `malloc()` was `2147483645` bytes.
