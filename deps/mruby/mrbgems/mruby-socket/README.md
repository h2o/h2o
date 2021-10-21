mruby-socket
============

"mruby-socket" mrbgem provides BSD socket interface for mruby.
API is compatible with CRuby's "socket" library.


## Example
```sh
% vi kame.rb
s = TCPSocket.open("www.kame.net", 80)
s.write("GET / HTTP/1.0\r\n\r\n")
puts s.read
s.close

% mruby kame.rb
HTTP/1.1 200 OK
Date: Tue, 21 May 2013 04:31:30 GMT
...
```

## Requirement
- [iij/mruby-io](https://github.com/iij/mruby-io) mrbgem
- [iij/mruby-mtest](https://github.com/iij/mruby-mtest) mrgbem to run tests
- system must have RFC3493 basic socket interface
- and some POSIX API...

## TODO
- add missing methods
- write more tests
- fix possible descriptor leakage (see XXX comments)
- `UNIXSocket#recv_io` `UNIXSocket#send_io`


## License

Copyright (c) 2013 Internet Initiative Japan Inc.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
