#!/bin/sh
#
# Print the reports that the sanitizer wrote, and fail if there are any.
#
# The undefined behaviour sanitizer is run in the recoverable mode, so that a
# report does not stop the process that made it: a killed server leaves the
# test that is talking to it waiting forever, and the job then dies of the
# workflow timeout instead of reporting the defect. The reports are written to
# files (the log_path of the sanitizer) rather than to the standard error of
# the process, because the standard error of the server under test ends up in
# a file of the test's temporary directory, which is deleted when the test
# ends. Nothing else would ever see them.
#
# usage: ubsan-report.sh <directory>
#   The directory is the log_path of the sanitizer; the reports are in the
#   files named <directory>.<pid>. An empty argument means that the build is
#   not instrumented, and there is nothing to report.

set -u

dir="${1:-}"

if [ -z "$dir" ]; then
    exit 0
fi

found=0
for f in "$dir".*; do
    [ -f "$f" ] || continue
    found=1
    echo "=== $f ==="
    cat "$f"
done

if [ "$found" -ne 0 ]; then
    echo "the sanitizer reported undefined behaviour; see the reports above" >&2
    exit 1
fi

exit 0
