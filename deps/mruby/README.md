[![Build Status][build-status-img]][travis-ci]

## What's mruby

mruby is the lightweight implementation of the Ruby language complying to (part
of) the [ISO standard][ISO-standard].  Its syntax is Ruby 1.9 compatible.

mruby can be linked and embedded within your application.  We provide the
interpreter program "mruby" and the interactive mruby shell "mirb" as examples.
You can also compile Ruby programs into compiled byte code using the mruby
compiler "mrbc".  All those tools reside in the "bin" directory.  "mrbc" is
also able to generate compiled byte code in a C source file, see the "mrbtest"
program under the "test" directory for an example.

This achievement was sponsored by the Regional Innovation Creation R&D Programs
of the Ministry of Economy, Trade and Industry of Japan.


## How to get mruby

The stable version 1.1.0 of mruby can be downloaded via the following URL:

  https://github.com/mruby/mruby/archive/1.1.0.zip

The latest development version of mruby can be downloaded via the following URL:

  https://github.com/mruby/mruby/zipball/master

The trunk of the mruby source tree can be checked out with the
following command:

    $ git clone https://github.com/mruby/mruby.git


## mruby home-page

The URL of the mruby home-page is:

  http://www.mruby.org/


## Mailing list

We don't have mailing list, use GitHub forum <http://github.com/mruby/mruby>.


## How to compile and install (mruby and gems)

See the [doc/compile/README.md](doc/compile/README.md) file.


## Running Tests

To run the tests, execute the following from the project's root directory.

    $ make test

Or

    $ ruby ./minirake test


## How to customize mruby (mrbgems)

mruby contains a package manager called *mrbgems*. To create extensions
in C and/or Ruby you should create a *GEM*. For a documentation of how to
use mrbgems consult the file [doc/mrbgems/README.md](doc/mrbgems/README.md). For example code of
how to use mrbgems look into the folder *examples/mrbgems/*.


## License

Copyright (c) 2015 mruby developers

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


## Note for License

mruby has chosen a MIT License due to its permissive license allowing
developers to target various environments such as embedded systems.
However, the license requires the display of the copyright notice and license
information in manuals for instance. Doing so for big projects can be
complicated or troublesome.  This is why mruby has decided to display "mruby
developers" as the copyright name to make it simple conventionally.
In the future, mruby might ask you to distribute your new code
(that you will commit,) under the MIT License as a member of
"mruby developers" but contributors will keep their copyright.
(We did not intend for contributors to transfer or waive their copyrights,
Actual copyright holder name (contributors) will be listed in the AUTHORS
file.)

Please ask us if you want to distribute your code under another license.


## How to Contribute

See the [contribution guidelines][contribution-guidelines] then send a pull
request to <http://github.com/mruby/mruby>.  We consider you have granted
non-exclusive right to your contributed code under MIT license.  If you want to
be named as one of mruby developers, please include an update to the AUTHORS
file in your pull request.

[ISO-standard]: http://www.iso.org/iso/iso_catalogue/catalogue_tc/catalogue_detail.htm?csnumber=59579
[build-status-img]: https://travis-ci.org/mruby/mruby.png?branch=master
[contribution-guidelines]: https://github.com/mruby/mruby/blob/master/CONTRIBUTING.md
[travis-ci]: https://travis-ci.org/mruby/mruby

