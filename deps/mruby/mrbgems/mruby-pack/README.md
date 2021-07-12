mruby-pack (pack / unpack)
=========

mruby-pack provides `Array#pack` and `String#unpack` for mruby.


## Installation
Add the line below into your `build_config.rb`:

```
  conf.gem :github => 'iij/mruby-pack'
```

There is no dependency on other mrbgems.


## Supported template string
 - A : arbitrary binary string (space padded, count is width)
 - a : arbitrary binary string (null padded, count is width)
 - C : 8-bit unsigned (unsigned char)
 - c : 8-bit signed (signed char)
 - D, d: 64-bit float, native format
 - E : 64-bit float, little endian byte order
 - e : 32-bit float, little endian byte order
 - F, f: 32-bit float, native format
 - G : 64-bit float, network (big-endian) byte order
 - g : 32-bit float, network (big-endian) byte order
 - H : hex string (high nibble first)
 - h : hex string (low nibble first)
 - I : unsigned integer, native endian (`unsigned int` in C)
 - i : signed integer, native endian (`int` in C)
 - L : 32-bit unsigned, native endian (`uint32_t`)
 - l : 32-bit signed, native endian (`int32_t`)
 - m : base64 encoded string (see RFC 2045, count is width)
 - N : 32-bit unsigned, network (big-endian) byte order
 - n : 16-bit unsigned, network (big-endian) byte order
 - Q : 64-bit unsigned, native endian (`uint64_t`)
 - q : 64-bit signed, native endian (`int64_t`)
 - S : 16-bit unsigned, native endian (`uint16_t`)
 - s : 16-bit signed, native endian (`int16_t`)
 - U : UTF-8 character
 - V : 32-bit unsigned, VAX (little-endian) byte order
 - v : 16-bit unsigned, VAX (little-endian) byte order
 - x : null byte
 - Z : same as "a", except that null is added with *



## License

Copyright (c) 2012 Internet Initiative Japan Inc.
Copyright (c) 2017 mruby developers

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

