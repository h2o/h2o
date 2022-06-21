# mrbgems

mrbgems is a library manager to integrate C and Ruby extension in an easy and
standardised way into mruby. Conventionally, each mrbgem name is prefixed by
`mruby-`, e.g. `mruby-time` for a gem that provides `Time` class functionality.

## Usage

You have to activate mrbgems explicitly in your build configuration.  To add
a gem, add the following line to your build configuration file, for example:

```ruby
conf.gem '/path/to/your/gem/dir'
```

You can also use a relative path to specify a gem.

```ruby
conf.gem 'examples/mrbgems/ruby_extension_example'
```

In that case,

* if your build configuration file is in the `build_config` directory, it's
  relative from `MRUBY_ROOT`.
* otherwise, it is relative from the directory where your build configuration is.

A remote GIT repository location for a GEM is also supported:

```ruby
conf.gem :git => 'https://github.com/masuidrive/mrbgems-example.git', :branch => 'master'
conf.gem :github => 'masuidrive/mrbgems-example', :branch => 'master'
conf.gem :bitbucket => 'mruby/mrbgems-example', :branch => 'master'
```

You can specify the subdirectory of the repository with `:path` option:

```ruby
conf.gem github: 'mruby/mruby', path: 'mrbgems/mruby-socket'
```

To use mrbgem from [mgem-list](https://github.com/mruby/mgem-list) use `:mgem` option:

```ruby
conf.gem :mgem => 'mruby-yaml'
conf.gem :mgem => 'yaml' # 'mruby-' prefix could be omitted
```

For specifying the commit hash to checkout use `:checksum_hash` option:

```ruby
conf.gem mgem: 'mruby-redis', checksum_hash: '3446d19fc4a3f9697b5ddbf2a904f301c42f2f4e'
```

If there are missing dependencies, mrbgem dependencies solver will reference
mrbgem from the core or mgem-list.

To pull all gems from remote GIT repository on build, call `rake -p`,
or `rake --pull-gems`.

NOTE: `:bitbucket` option supports only git. Hg is unsupported in this version.

## GemBox

There are instances when you wish to add a collection of mrbgems into mruby at
once, or be able to substitute mrbgems based on configuration, without having to
add each gem to your build configuration file.  A packaged collection of mrbgems
is called a GemBox.  A GemBox is a file that contains a list of mrbgems to load
into mruby, in the same format as if you were adding them to the build config
via `config.gem`, but wrapped in an `MRuby::GemBox` object.  GemBoxes are
loaded into mruby via `config.gembox 'boxname'`.

Below we have created a GemBox containing `mruby-time` and `mrbgems-example`:

```ruby
MRuby::GemBox.new do |conf|
  conf.gem "#{root}/mrbgems/mruby-time"
  conf.gem :github => 'masuidrive/mrbgems-example'
end
```

As mentioned, the GemBox uses the same conventions as `MRuby::Build`.  The GemBox
must be saved with a `.gembox` extension inside the `mrbgems` directory to be
picked up by mruby.

To use this example GemBox, we save it as `custom.gembox` inside the `mrbgems`
directory in mruby, and add the following to your build configuration file inside
the build block:

```ruby
conf.gembox 'custom'
```

This will cause the `custom` GemBox to be read in during the build process,
adding `mruby-time` and `mrbgems-example` to the build.

If you want, you can put GemBox outside of mruby directory. In that case you must
specify an absolute path like below.

```ruby
conf.gembox "#{ENV["HOME"]}/mygemboxes/custom"
```

There are two GemBoxes that ship with mruby: [default](../../mrbgems/default.gembox)
and [full-core](../../mrbgems/full-core.gembox). The [default](../../mrbgems/default.gembox) GemBox
contains several core components of mruby, and [full-core](../../mrbgems/full-core.gembox)
contains every gem found in the `mrbgems` directory.

## GEM Structure

The maximal GEM structure looks like this:

```
+- GEM_NAME             <- Name of GEM
    |
    +- README.md        <- Readme for GEM
    |
    +- mrbgem.rake      <- GEM Specification
    |
    +- include/         <- Header for Ruby extension (will exported)
    |
    +- mrblib/          <- Source for Ruby extension
    |
    +- src/             <- Source for C extension
    |
    +- tools/           <- Source for Executable (in C)
    |
    +- test/            <- Test code (Ruby)
```

The folder `mrblib` contains pure Ruby files to extend mruby. The folder `src`
contains C/C++ files to extend mruby. The folder `include` contains C/C++ header
files. The folder `test` contains C/C++ and pure Ruby files for testing purposes
which will be used by `mrbtest`. `mrbgem.rake` contains the specification
to compile C and Ruby files. `README.md` is a short description of your GEM.

## Build process

mrbgems expects a specification file called `mrbgem.rake` inside of your
GEM directory. A typical GEM specification could look like this for example:

```ruby
MRuby::Gem::Specification.new('c_and_ruby_extension_example') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'Example mrbgem using C and ruby'
end
```

The mrbgems build process will use this specification to compile Object and Ruby
files. The compilation results will be added to `lib/libmruby.a`. This file exposes
the GEM functionality to tools like `mruby` and `mirb`.

The following properties can be set inside your `MRuby::Gem::Specification` for
information purpose:

* `spec.license` or `spec.licenses` (A single license or a list of them under which this GEM is licensed)
* `spec.author` or `spec.authors` (Developer name or a list of them)
* `spec.version` (Current version)
* `spec.description` (Detailed description)
* `spec.summary`
  * One line short description of mrbgem.
  * Printed in build summary of rake when set.
* `spec.homepage` (Homepage)
* `spec.requirements` (External requirements as information for user)

The `license` and `author` properties are required in every GEM!

In case your GEM is depending on other GEMs please use
`spec.add_dependency(gem, *requirements[, default_get_info])` like:

```ruby
MRuby::Gem::Specification.new('c_and_ruby_extension_example') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'

  # Add GEM dependency mruby-parser.
  # The version must be between 1.0.0 and 1.5.2 .
  spec.add_dependency('mruby-parser', '>= 1.0.0', '<= 1.5.2')

  # Use any version of mruby-uv from GitHub.
  spec.add_dependency('mruby-uv', '>= 0.0.0', :github => 'mattn/mruby-uv')

  # Use latest mruby-onig-regexp from GitHub. (version requirements can be omitted)
  spec.add_dependency('mruby-onig-regexp', :github => 'mattn/mruby-onig-regexp')

  # You can add extra mgems active only on test
  spec.add_test_dependency('mruby-process', :github => 'iij/mruby-process')
end
```

The version requirements and default gem information are optional.

Version requirement supports following operators:

* '=': is equal
* '!=': is not equal
* '>': is greater
* '<': is lesser
* '>=': is equal or greater
* '<=': is equal or lesser
* '~>': is equal or greater and is lesser than the next major version
  * example 1: '~> 2.2.2' means '>= 2.2.2' and '< 2.3.0'
  * example 2: '~> 2.2'   means '>= 2.2.0' and '< 3.0.0'

When more than one version requirements is passed, the dependency must satisfy all of it.

You can have default gem to use as dependency when it's not defined in your build configuration.
When the last argument of `add_dependency` call is `Hash`, it will be treated as default gem information.
Its format is same as argument of method `MRuby::Build#gem`, expect that it can't be treated as path gem location.

When a special version of dependency is required,
use `MRuby::Build#gem` in the build configuration to override default gem.

If you have conflicting GEMs use the following method:

* `spec.add_conflict(gem, *requirements)`
  * The `requirements` argument is same as in `add_dependency` method.

like following code:

```ruby
MRuby::Gem::Specification.new 'some-regexp-binding' do |spec|
  spec.license = 'BSD'
  spec.author = 'John Doe'

  spec.add_conflict 'mruby-onig-regexp', '> 0.0.0'
  spec.add_conflict 'mruby-hs-regexp'
  spec.add_conflict 'mruby-pcre-regexp'
  spec.add_conflict 'mruby-regexp-pcre'
end
```

In case your GEM has more complex build requirements you can use
the following options additionally inside your GEM specification:

* `spec.cc.flags` (C compiler flags)
* `spec.cc.defines` (C compiler defines)
* `spec.cc.include_paths` (C compiler include paths)
* `spec.linker.flags` (Linker flags)
* `spec.linker.libraries` (Linker libraries)
* `spec.linker.library_paths` (Linker additional library path)
* `spec.bins` (Generate binary file)
* `spec.rbfiles` (Ruby files to compile)
* `spec.objs` (Object files to compile)
* `spec.test_rbfiles` (Ruby test files for integration into mrbtest)
* `spec.test_objs` (Object test files for integration into mrbtest)
* `spec.test_preload` (Initialization files for mrbtest)

You also can use `spec.mruby.cc` and `spec.mruby.linker` to add extra global parameters for the compiler and linker.

### include_paths and dependency

Your GEM can export include paths to another GEMs that depends on your GEM.
By default, `/...absolute path.../{GEM_NAME}/include` will be exported.
So it is recommended not to put GEM's local header files on include/.

These exports are retroactive.
For example: when B depends on C and A depends on B, A will get include paths exported by C.

Exported include_paths are automatically appended to GEM local include_paths by rake.
You can use `spec.export_include_paths` accessor if you want more complex build.

## C Extension

mruby can be extended with C. This is possible by using the C API to
integrate C libraries into mruby.

### Preconditions

mrbgems expects that you have implemented a C method called
`mrb_YOURGEMNAME_gem_init(mrb_state)`. `YOURGEMNAME` will be replaced
by the name of your GEM. If you call your GEM `c_extension_example`, your
initialisation method could look like this:

```c
void
mrb_c_extension_example_gem_init(mrb_state* mrb) {
  struct RClass *class_cextension = mrb_define_module(mrb, "CExtension");
  mrb_define_class_method(mrb, class_cextension, "c_method", mrb_c_method, MRB_ARGS_NONE());
}
```

### Finalize

mrbgems expects that you have implemented a C method called
`mrb_YOURGEMNAME_gem_final(mrb_state)`. `YOURGEMNAME` will be replaced
by the name of your GEM. If you call your GEM `c_extension_example`, your
finalizer method could look like this:

```c
void
mrb_c_extension_example_gem_final(mrb_state* mrb) {
  free(someone);
}
```

### Example

```
+- c_extension_example/
    |
    +- README.md        (Optional)
    |
    +- src/
    |   |
    |   +- example.c    <- C extension source
    |
    +- test/
    |   |
    |   +- example.rb   <- Test code for C extension
    |
    +- mrbgem.rake      <- GEM specification
```

## Ruby Extension

mruby can be extended with pure Ruby. It is possible to override existing
classes or add new ones in this way. Put all Ruby files into the `mrblib`
folder.

### Pre-Conditions

none

### Example

```
+- ruby_extension_example/
    |
    +- README.md        (Optional)
    |
    +- mrblib/
    |   |
    |   +- example.rb   <- Ruby extension source
    |
    +- test/
    |   |
    |   +- example.rb   <- Test code for Ruby extension
    |
    +- mrbgem.rake      <- GEM specification
```

## C and Ruby Extension

mruby can be extended with C and Ruby at the same time. It is possible to
override existing classes or add new ones in this way. Put all Ruby files
into the `mrblib` folder and all C files into the `src` folder.

mruby codes under `mrblib` directory would be executed after gem init C
function is called. Make sure *mruby script* depends on *C code* and
*C code* doesn't depend on *mruby script*.

### Pre-Conditions

See C and Ruby example.

### Example

```
+- c_and_ruby_extension_example/
    |
    +- README.md        (Optional)
    |
    +- mrblib/
    |   |
    |   +- example.rb   <- Ruby extension source
    |
    +- src/
    |   |
    |   +- example.c    <- C extension source
    |
    +- test/
    |   |
    |   +- example.rb   <- Test code for C and Ruby extension
    |
    +- mrbgem.rake      <- GEM specification
```

## Binary gems

Some gems can generate executables under `bin` directory. Those gems are called
binary gems.  Names of binary gems are conventionally prefixed by `mruby-bin`,
e.g. `mruby-bin-mirb` and `mruby-bin-strip`.

To specify the name of executable, you need to specify `spec.bins` in the
`mrbgem.rake`. The entry point `main()` should be in the C source file under
`tools/<bin>/*.c` where `<bin>` is a name of the executable. C files under the
`<bin>` directory are compiled and linked to the executable, but not included in
`libmruby.a`, whereas files under `mrblib` and `src` are.

It is strongly recommended not to include `mrblib` and `src` directories in the
binary gems, to separate normal gems and binary gems.

### Example

```
+- mruby-bin-example/
    |
    +- README.md        (Optional)
    |
    +- bintest/
    |   |
    |   +- example.rb   <- Test code for binary gem
    |
    +- mrbgem.rake      <- Gem specification
    |
    +- mrblib/          <- Source for Ruby extension (Optional)
    |
    +- src/             <- Source for C extension (Optional)
    |
    +- tools/
        |
        +- example/     <- Executable name directory
        |
        +- example.c    <- Source for Executable (includes main)
```
