# How to contribute

mruby is an open-source project which is looking forward to each contribution.
Contributors agree to license their contribution(s) under MIT license.

## Your Pull Request

To make it easy to review and understand your change please keep the following
things in mind before submitting your pull request:

* Work on the latest possible state of **mruby/master**
* Create a branch which is dedicated to your change
* Test your changes before creating a pull request (```rake test```)
* If possible write a test case which confirms your change
* Don't mix several features or bug-fixes in one pull request
* Create a meaningful commit message
* Explain your change (i.e. with a link to the issue you are fixing)
* Use mrbgem to provide non ISO features (classes, modules and methods) unless
  you have a special reason to implement them in the core

## Coding conventions

How to style your C and Ruby code which you want to submit.

### C code

The core part (parser, bytecode-interpreter, core-lib, etc.) of mruby is
written in the C programming language. Please note the following hints for your
C code:

#### Comply with C99 (ISO/IEC 9899:1999)

mruby should be highly portable to other systems and compilers. For this it is
recommended to keep your code as close as possible to the C99 standard
(http://www.open-std.org/jtc1/sc22/WG14/www/docs/n1256.pdf).

Visual C++ is also an important target for mruby (supported version is 2013 or
later). For this reason features that are not supported by Visual C++ may not
be used (e.g. `%z` of `strftime()`).

NOTE: Old GCC requires `-std=gnu99` option to enable C99 support.

#### Reduce library dependencies to a minimum

The dependencies to libraries should be kept to an absolute minimum. This
increases the portability but makes it also easier to cut away parts of mruby
on-demand.

#### Insert a break after the function return value:

    ```C
    int
    main(void)
    {
      ...
    }
    ```

### Ruby code

Parts of the standard library of mruby are written in the Ruby programming
language itself. Please note the following hints for your Ruby code:

#### Comply with the Ruby standard (ISO/IEC 30170:2012)

mruby is currently targeting to execute Ruby code which complies to ISO/IEC
30170:2012 (https://www.iso.org/iso/iso_catalogue/catalogue_tc/catalogue_detail.htm?csnumber=59579),
unless there's a clear reason, e.g. the latest Ruby has changed behavior from ISO.
