mruby-digest
=========

This library is a fork of [github.com/iij/mruby-digest](https://github.com/iij/mruby-digest).
Unlike the original, this fork does not have any dependencies; it uses [picohash](https://github.com/kazuho/picohash) - a public domain library for hash calculation.

## Features

Message Digest and HMAC classes are available.  They are compatible with CRuby's ones.

- Digest::MD5, Digest::RMD160, Digest::SHA1, Digest::SHA256, Digest::SHA384 and
  Digest::SHA512
  - Note: some of them are not available if libcrypto.a does not support them on your system.
- Digest::HMAC

## Install
 - add conf.gem line to `build_config.rb`

```ruby
MRuby::Build.new do |conf|

    # ... (snip) ...

    conf.gem :git => 'https://github.com/iij/mruby-digest.git'
end
```

## Usage
```ruby
Digest::MD5.digest('ruby')
Digest::MD5.hexdigest('ruby')
```

## License

Copyright (c) 2012-2015 Internet Initiative Japan Inc., Kazuho Oku

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

