- To build the fuzzer pass `-DBUILD_FUZZER=ON` to `cmake`, this will
  instrument `libh2o`, and build two fuzzer programs: `h2o-fuzzer-http1` and
  `h2o-fuzzer-http2`
- The corpuses where built running the unit tests, and files generated using
  `fuzz/gather-data.patch`
- To run the fuzzer standlone do:
  `ASAN_OPTIONS=detect_leaks=0 ./h2o-fuzzer-http1 -max_len=$((16 * 1024 )) fuzz/http1-corpus`
  or
  `ASAN_OPTIONS=detect_leaks=0 ./h2o-fuzzer-http2 -max_len=$((16 * 1024 )) fuzz/http2-corpus`
