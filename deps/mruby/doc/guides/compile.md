# Compile

mruby uses Rake to compile and cross-compile all libraries and
binaries.

## Prerequisites

To compile mruby out of the source code you need the following tools:
* C Compiler (i.e. ```gcc```)
* Linker (i.e. ```gcc```)
* Archive utility (i.e. ```ar```)
* Parser generator (i.e. ```bison```)
* Ruby 1.8 or 1.9 (i.e. ```ruby``` or ```jruby```)

Optional:
* GIT (to update mruby source and integrate mrbgems easier)
* C++ compiler (to use GEMs which include \*.cpp, \*.cxx, \*.cc)
* Assembler (to use GEMs which include \*.asm)

## Usage

Inside of the root directory of the mruby source a file exists
called *build_config.rb*. This file contains the build configuration
of mruby and looks like this for example:
```ruby
MRuby::Build.new do |conf|
  toolchain :gcc
end
```

All tools necessary to compile mruby can be set or modified here. In case
you want to maintain an additional *build_config.rb* you can define a
customized path using the *$MRUBY_CONFIG* environment variable.

To compile just call ```./minirake``` inside of the mruby source root. To
generate and execute the test tools call ```./minirake test```. To clean
all build files call ```./minirake clean```. To see full command line on
build, call ```./minirake -v```.

## Build Configuration

Inside of the *build_config.rb* the following options can be configured
based on your environment.

### Toolchains

The mruby build system already contains a set of toolchain templates which
configure the build environment for specific compiler infrastructures.

#### GCC

Toolchain configuration for the GNU C Compiler.
```ruby
toolchain :gcc
```

#### clang

Toolchain configuration for the LLVM C Compiler clang. Mainly equal to the
GCC toolchain.
```ruby
toolchain :clang
```

#### Visual Studio 2010, 2012 and 2013

Toolchain configuration for Visual Studio on Windows. If you use the
[Visual Studio Command Prompt](http://msdn.microsoft.com/en-us/library/ms229859\(v=vs.110\).aspx),
you normally do not have to specify this manually, since it gets automatically detected by our build process.
```ruby
toolchain :visualcpp
```

#### Android

Toolchain configuration for Android.
```ruby
toolchain :android
```

Requires the custom standalone Android NDK and the toolchain path
in ```ANDROID_STANDALONE_TOOLCHAIN```.

### Binaries

It is possible to select which tools should be compiled during the compilation
process. The following tools can be selected:
* mruby (mruby interpreter)
* mirb (mruby interactive shell)

To select them declare conf.gem as follows:
```ruby
conf.gem "#{root}/mrbgems/mruby-bin-mruby"
conf.gem "#{root}/mrbgems/mruby-bin-mirb"
```

### File Separator

Some environments require a different file separator character. It is possible to
set the character via ```conf.file_separator```.
```ruby
conf.file_separator = '/'
```

### C Compiler

Configuration of the C compiler binary, flags and include paths.
```ruby
conf.cc do |cc|
  cc.command = ...
  cc.flags = ...
  cc.include_paths = ...
  cc.defines = ...
  cc.option_include_path = ...
  cc.option_define = ...
  cc.compile_options = ...
end
```

C Compiler has header searcher to detect installed library.

If you need a include path of header file use ```search_header_path```:
```ruby
# Searches ```iconv.h```.
# If found it will return include path of the header file.
# Otherwise it will return nil .
fail 'iconv.h not found' unless conf.cc.search_header_path 'iconv.h'
```

If you need a full file name of header file use ```search_header```:
```ruby
# Searches ```iconv.h```.
# If found it will return full path of the header file.
# Otherwise it will return nil .
iconv_h = conf.cc.search_header 'iconv.h'
print "iconv.h found: #{iconv_h}\n"
```

Header searcher uses compiler's ```include_paths``` by default.
When you are using GCC toolchain (including clang toolchain since its base is gcc toolchain)
it will use compiler specific include paths too. (For example ```/usr/local/include```, ```/usr/include```)

If you need a special header search paths define a singleton method ```header_search_paths``` to C compiler:
```ruby
def conf.cc.header_search_paths
  ['/opt/local/include'] + include_paths
end
```

### Linker

Configuration of the Linker binary, flags and library paths.
```ruby
conf.linker do |linker|
  linker.command = ...
  linker.flags = ...
  linker.flags_before_libraries = ...
  linker.libraries = ...
  linker.flags_after_libraries = ...
  linker.library_paths = ....
  linker.option_library = ...
  linker.option_library_path = ...
  linker.link_options = ...
end
```

### Archiver

Configuration of the Archiver binary and flags.
```ruby
conf.archiver do |archiver|
  archiver.command = ...
  archiver.archive_options = ...
end
```

### Parser Generator

Configuration of the Parser Generator binary and flags.
```ruby
conf.yacc do |yacc|
  yacc.command = ...
  yacc.compile_options = ...
end
```

### GPerf

Configuration of the GPerf binary and flags.
```ruby
conf.gperf do |gperf|
  gperf.command = ...
  gperf.compile_options = ...
end
```

### File Extensions
```ruby
conf.exts do |exts|
  exts.object = ...
  exts.executable = ...
  exts.library = ...
end
```

### Mrbgems

Integrate GEMs in the build process.
```ruby
# Integrate GEM with additional configuration
conf.gem 'path/to/gem' do |g|
  g.cc.flags << ...
end

# Integrate GEM without additional configuration
conf.gem 'path/to/another/gem'
```

See doc/mrbgems/README.md for more option about mrbgems.

### Mrbtest

Configuration Mrbtest build process.

If you want mrbtest.a only, You should set ```conf.build_mrbtest_lib_only```
```ruby
conf.build_mrbtest_lib_only
```

### Bintest

Tests for mrbgem tools using CRuby.
To have bintests place \*.rb scripts to ```bintest/``` directory of mrbgems.
See ```mruby-bin-*/bintest/*.rb``` if you need examples.
If you want a temporary files use `tempfile` module of CRuby instead of ```/tmp/```.

You can enable it with following:
```ruby
conf.enable_bintest
```

### C++ ABI

mruby can use C++ exception to raise exception internally.
It is called C++ ABI mode.
By using C++ exception it can release C++ stack object correctly.
Whenever you mix C++ code C++ ABI mode would be enabled automatically.
If you need to enable C++ ABI mode explicitly add the following:
```ruby
conf.enable_cxx_abi
```

#### C++ exception disabling.

If you need to force C++ exception disable
(For example using a compiler option to disable C++ exception)
add following:
```ruby
conf.disable_cxx_exception
```

Note that it must be called before ```enable_cxx_abi``` or ```gem``` method.

### Debugging mode

To enable debugging mode add the following:
```ruby
conf.enable_debug
```

When debugging mode is enabled
* Macro ```MRB_DEBUG``` would be defined.
	* Which means ```mrb_assert()``` macro is enabled.
* Debug information of irep would be generated by ```mrbc```.
	* Because ```-g``` flag would be added to ```mrbc``` runner.
    * You can have better backtrace of mruby scripts with this.

## Cross-Compilation

mruby can also be cross-compiled from one platform to another. To
achieve this the *build_config.rb* needs to contain an instance of
```MRuby::CrossBuild```. This instance defines the compilation
tools and flags for the target platform. An example could look
like this:
```ruby
MRuby::CrossBuild.new('32bit') do |conf|
  toolchain :gcc

  conf.cc.flags << "-m32"
  conf.linker.flags << "-m32"
end
```

All configuration options of ```MRuby::Build``` can also be used
in ```MRuby::CrossBuild```.

### Mrbtest in Cross-Compilation

In cross compilation, you can run ```mrbtest``` on emulator if
you have it by changing configuration of test runner.
```ruby
conf.test_runner do |t|
  t.command = ... # set emulator. this value must be non nil or false
  t.flags = ... # set flags of emulator

  def t.run(bin) # override `run` if you need to change the behavior of it
    ... # `bin` is the full path of mrbtest
  end
end
```

## Build process

During the build process the directory *build* will be created in the
root directory. The structure of this directory will look like this:

	+- build
	   |
	   +-  host
	       |
	       +- bin          <- Binaries (mirb, mrbc and mruby)
	       |
	       +- lib          <- Libraries (libmruby.a and libmruby_core.a)
	       |
	       +- mrblib
	       |
	       +- src
	       |
	       +- test         <- mrbtest tool
	       |
	       +- tools
	          |
	          +- mirb
	          |
	          +- mrbc
	          |
	          +- mruby

The compilation workflow will look like this:
* compile all files under *src* (object files will be stored
in *build/host/src*)
* generate parser grammar out of *src/parse.y* (generated
result will be stored in *build/host/src/y.tab.c*)
* compile  *build/host/src/y.tab.c* to  *build/host/src/y.tab.o*
* create *build/host/lib/libmruby_core.a* out of all object files (C only)
* create ```build/host/bin/mrbc``` by compiling *tools/mrbc/mrbc.c* and
linking with *build/host/lib/libmruby_core.a*
* create *build/host/mrblib/mrblib.c* by compiling all \*.rb files
under *mrblib* with ```build/host/bin/mrbc```
* compile *build/host/mrblib/mrblib.c* to *build/host/mrblib/mrblib.o*
* create *build/host/lib/libmruby.a* out of all object files (C and Ruby)
* create ```build/host/bin/mruby``` by compiling *mrbgems/mruby-bin-mruby/tools/mruby/mruby.c* and
linking with *build/host/lib/libmruby.a*
* create ```build/host/bin/mirb``` by compiling *mrbgems/mruby-bin-mirb/tools/mirb/mirb.c* and
linking with *build/host/lib/libmruby.a*

```
 _____    _____    ______    ____    ____    _____    _____    ____
| CC  |->|GEN  |->|AR    |->|CC  |->|CC  |->|AR   |->|CC   |->|CC  |
| *.c |  |y.tab|  |core.a|  |mrbc|  |*.rb|  |lib.a|  |mruby|  |mirb|
 -----    -----    ------    ----    ----    -----    -----    ----
```

### Cross-Compilation

In case of a cross-compilation to *i386* the *build* directory structure looks
like this:

	+- build
	   |
	   +-  host
	   |   |
	   |   +- bin           <- Native Binaries
	   |   |
	   |   +- lib           <- Native Libraries
	   |   |
	   |   +- mrblib
	   |   |
	   |   +- src
	   |   |
	   |   +- test          <- Native mrbtest tool
	   |   |
	   |   +- tools
	   |      |
	   |      +- mirb
	   |      |
	   |      +- mrbc
	   |      |
	   |      +- mruby
	   +- i386
	      |
	      +- bin            <- Cross-compiled Binaries
	      |
	      +- lib            <- Cross-compiled Libraries
	      |
	      +- mrblib
	      |
	      +- src
	      |
	      +- test           <- Cross-compiled mrbtest tool
	      |
	      +- tools
	         |
	         +- mirb
	         |
	         +- mrbc
	         |
	         +- mruby

An extra directory is created for the target platform. In case you
compile for *i386* a directory called *i386* is created under the
build directory.

The cross compilation workflow starts in the same way as the normal
compilation by compiling all *native* libraries and binaries.
Afterwards the cross compilation process proceeds like this:
* cross-compile all files under *src* (object files will be stored
in *build/i386/src*)
* generate parser grammar out of *src/parse.y* (generated
result will be stored in *build/i386/src/y.tab.c*)
* cross-compile *build/i386/src/y.tab.c* to *build/i386/src/y.tab.o*
* create *build/i386/mrblib/mrblib.c* by compiling all \*.rb files
under *mrblib* with the native ```build/host/bin/mrbc```
* cross-compile *build/host/mrblib/mrblib.c* to *build/host/mrblib/mrblib.o*
* create *build/i386/lib/libmruby.a* out of all object files (C and Ruby)
* create ```build/i386/bin/mruby``` by cross-compiling *mrbgems/mruby-bin-mruby/tools/mruby/mruby.c* and
linking with *build/i386/lib/libmruby.a*
* create ```build/i386/bin/mirb``` by cross-compiling *mrbgems/mruby-bin-mirb/tools/mirb/mirb.c* and
linking with *build/i386/lib/libmruby.a*
* create *build/i386/lib/libmruby_core.a* out of all object files (C only)
* create ```build/i386/bin/mrbc``` by cross-compiling *tools/mrbc/mrbc.c* and
linking with *build/i386/lib/libmruby_core.a*

```
 _______________________________________________________________
|              Native Compilation for Host System               |
|  _____      ______      _____      ____      ____      _____  |
| | CC  | -> |AR    | -> |GEN  | -> |CC  | -> |CC  | -> |AR   | |
| | *.c |    |core.a|    |y.tab|    |mrbc|    |*.rb|    |lib.a| |
|  -----      ------      -----      ----      ----      -----  |
 ---------------------------------------------------------------
                                ||
                               \||/
                                \/
 ________________________________________________________________
|             Cross Compilation for Target System                |
|  _____      _____      _____      ____      ______      _____  |
| | CC  | -> |AR   | -> |CC   | -> |CC  | -> |AR    | -> |CC   | |
| | *.c |    |lib.a|    |mruby|    |mirb|    |core.a|    |mrbc | |
|  -----      -----      -----      ----      ------      -----  |
 ----------------------------------------------------------------
```

## Build Configuration Examples

### Minimal Library

To build a minimal mruby library you need to use the Cross Compiling
feature due to the reason that there are functions (i.e. stdio) which
can't be disabled for the main build.

```ruby
MRuby::CrossBuild.new('Minimal') do |conf|
  toolchain :gcc

  conf.cc.defines = %w(MRB_DISABLE_STDIO)
  conf.bins = []
end
```

This configuration defines a cross compile build called 'Minimal' which
is using the GCC and compiles for the host machine. It also disables
all usages of stdio and doesn't compile any binaries (i.e. mrbc).

## Test Environment

mruby's build process includes a test environment. In case you start the testing
of mruby, a native binary called ```mrbtest``` will be generated and executed.
This binary contains all test cases which are defined under *test/t*. In case
of a cross-compilation an additional cross-compiled *mrbtest* binary is
generated. You can copy this binary and run on your target system.
