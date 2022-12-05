# Linking `libmruby` to your application

You have two ways to link `libmruby` to your application.

* using executable gem.
* using normal compilation process

## Executable Gems

If your application is relatively small, `mrbgem` is an easier way to
create the executable.  By tradition, the gem name start with
`mruby-bin-`, e.g. `mruby-bin-debugger`.

### `mrbgem.rake` file

The executable name is specified in `mrbgem.rake` file at the top of
your `mrbgem` directory.

```ruby
MRuby::Gem::Specification.new('mruby-bin-example') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'Example for executable command gem'
  spec.bins = %w(mruby-example)    # <- this is binary name
end
```

### Source tree structure

The source file for the gem executable should be in
`<gem-name>/tools/<bin-name>`.  Currently, we support C or C++ source code
(`.c`, `.cpp`, `.cxx`, `.cc`) for the executable. Ruby source files are not
supported. Put the functionality in the different gem and specify dependency to
it in `mrbgem.rake`.

## Normal compilation process

The `libmruby` is a normal library so that you can just link it to your
application. Specify proper compiler options (`-I` etc.) and linker options
(`-Lmruby` etc.) to compile and link your application. Specify those options in
your build script (e.g. `Makefile`).

### Compiler options

You need to specify compiler options that are compatible to mruby configuration,
for example:

* `-I` to specify the place for mruby header files
* `-D` to specify mruby configuration macros

To retrieve compiler options used to build `mruby`, you can use `mruby-config`
command with following options:

* `--cc`                    compiler name
* `--cflags`                options passed to compiler

```
$ mruby-config --cflags
-std=gnu99 -g -O3 -Wall -DMRB_GC_FIXED_ARENA -I/home/matz/work/mruby/include -I/home/matz/work/mruby/build/host/include
```

### Linker options

Just like compiler options, you need to specify linker options that are
compatible to mruby configuration.

To retrieve linker options, you can use `mruby-config` with following options:

* `--ld`                    linker name
* `--ldflags`               options passed to linker
* `--ldflags-before-libs`   options passed to linker before linked libraries
* `--libs`                  linked libraries

```
$ mruby-config --ldflags
-L/home/matz/work/mruby/build/host/lib

$ mruby-config --ldflags-before-libs
# <nothing in this case>

$ mruby-config --libs
-lmruby -lm
```
