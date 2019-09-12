/*
 * Copyright (c) 2019 Fastly, Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Below is an example bpftrace script that logs the events in JSON-logging
 * format.  The script can be invoked like:
 *
 * % sudo bpftrace -p $(pidof cli) /mydev/picotls/misc/dtrace/bpftrace.d
 */

usdt::picotls_new {
    printf("{\"addr\": \"%p\", \"event\": \"new\", \"is_server\": %d}\n", arg0, arg1);
}
usdt::picotls_free {
    printf("{\"addr\": \"%p\", \"event\": \"free\"}\n", arg0);
}
usdt::picotls_client_random {
    printf("{\"addr\": \"%p\", \"event\": \"client_random\"", arg0);
    printf(", \"bytes\": \"%s\"}\n", str(arg1));
}
usdt::picotls_new_secret {
    printf("\"addr\": \"%p\", \"event\": \"new_secret\"", arg0);
    printf(", \"label\": \"%s\", \"secret\": \"%s\"}\n", str(arg1), str(arg2));
}
