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
 * % sudo dtrace -c './cli 127.0.0.1 4433' -s misc/dtrace/dtrace.d
 */

picotls$target:::picotls_new {
    printf("\n{\"addr\": \"0x%p\", \"event\": \"new\", \"is_server\": %d}", arg0, arg1);
}
picotls$target:::picotls_free {
    printf("\n{\"addr\": \"0x%p\", \"event\": \"free\"}", arg0);
}
picotls$target:::picotls_client_random {
    printf("\n{\"addr\": \"0x%p\", \"event\": \"client_random\", \"bytes\": \"%s\"}", arg0, copyinstr(arg1));
}
picotls$target:::picotls_new_secret {
    printf("\n{\"addr\": \"0x%p\", \"event\": \"new_secret\", \"label\": \"%s\", \"secret\": \"%s\"}", arg0, copyinstr(arg1), copyinstr(arg2));
}
picotls$target:::picotls_receive_message {
    printf("\n{\"addr\": \"0x%p\", \"event\": \"receive_message\", \"type\": %d, \"ret\": %d}\n", arg0, arg1, arg4);
    tracemem(copyin(arg2, arg3), 65535, arg3);
}
