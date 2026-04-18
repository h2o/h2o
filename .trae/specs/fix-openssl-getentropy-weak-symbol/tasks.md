# Tasks
- [x] Task 1: Ensure `getentropy` is strongly referenced in `main.c`: Add a real call to `getentropy` inside the `if (dummy_zero != 0)` unreachable block.
  - [x] SubTask 1.1: Identify the `if (dummy_zero != 0)` block in `src/main.c`.
  - [x] SubTask 1.2: Add `#include <unistd.h>` if it's missing (though it might already be present).
  - [x] SubTask 1.3: Add `getentropy(NULL, 0);` inside the block to force the linker to extract it from `libc.a`.
- [x] Task 2: Validate the code compiles correctly and pushes a new commit to resolve the PR.

# Task Dependencies
- [Task 2] depends on [Task 1]
