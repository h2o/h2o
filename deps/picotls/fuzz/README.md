# Fuzzing

This directory contains code and test data for fuzz testing picotls with LLVM's [LibFuzzer](http://libfuzzer.info). 

## Building the test drivers

To build the fuzz test drivers (AKA "fuzz targets"), pass `-DBUILD_FUZZER=ON` to `cmake`. This this will instrument the binary and build fuzz targets. Note that you must have a version of LLVM Clang installed that supports LibFuzzer in order for this build to succeed.

## Test corpus information

There are seed test corpuses for some fuzz targets included. They are stored in the `fuzz` directory in a subdirectory corresponding to the fuzz target binary name.  See the [LibFuzzer docs](http://llvm.org/docs/LibFuzzer.html) for more information on using seed test corpuses.

## Submitting new seed files

This project welcomes seed files that exercise new paths in the target programs. Before submitting new seed files, please ensure they add coverage to the existing corpus via the driver `-merge` flag. For example:

```
$ ./fuzz-client-hello-merge=1 ./fuzz/fuzz-client-hello-corpus ./fuzz/my-new-seeds
```

See the [LibFuzzer docs](http://llvm.org/docs/LibFuzzer.html) for more information on minimizing test corpuses.

## Running the fuzzers

You will likely want to tailor fuzzer options to your execution environment, but here is a basic example of running a fuzzer:

```
./fuzz-client-hello fuzz/fuzz-client-hello-corpus
```
