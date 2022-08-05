# Cross Compiling configuration for the Nintendo GameBoyAdvance.
# This configuration requires devkitARM
# https://devkitpro.org/wiki/Getting_Started/devkitARM
#
# Tested only on GNU/Linux
#
MRuby::CrossBuild.new("gameboyadvance") do |conf|
  toolchain :gcc

  DEVKITPRO_PATH = "/opt/devkitpro"
  BIN_PATH = "#{DEVKITPRO_PATH}/devkitARM/bin"

  # C compiler
  conf.cc do |cc|
    cc.command = "#{BIN_PATH}/arm-none-eabi-gcc"
    cc.flags << ["-mthumb-interwork", "-mthumb", "-O2"]
    cc.compile_options = %(%{flags} -o "%{outfile}" -c "%{infile}")
  end

  # C++ compiler
  conf.cxx do |cxx|
    cxx.command = "#{BIN_PATH}/arm-none-eabi-g++"
    cxx.include_paths = conf.cc.include_paths.dup
    cxx.flags = conf.cc.flags.dup
    cxx.flags << %w[-fno-rtti -fno-exceptions]
    cxx.defines = conf.cc.defines.dup
    cxx.compile_options = conf.cc.compile_options.dup
  end

  # Linker
  conf.linker do |linker|
    linker.command = "#{BIN_PATH}/arm-none-eabi-gcc"
    linker.flags << ["-mthumb-interwork", "-mthumb", "-specs=gba.specs"]
  end

  # No executables
  conf.bins = []

  # Do not build executable test
  conf.build_mrbtest_lib_only

  # Disable C++ exception
  conf.disable_cxx_exception

  # Gems from core
  # removing mruby-io
  conf.gem core: "mruby-metaprog"
  conf.gem core: "mruby-pack"
  conf.gem core: "mruby-sprintf"
  conf.gem core: "mruby-print"
  conf.gem core: "mruby-math"
  conf.gem core: "mruby-time"
  conf.gem core: "mruby-struct"
  conf.gem core: "mruby-compar-ext"
  conf.gem core: "mruby-enum-ext"
  conf.gem core: "mruby-string-ext"
  conf.gem core: "mruby-numeric-ext"
  conf.gem core: "mruby-array-ext"
  conf.gem core: "mruby-hash-ext"
  conf.gem core: "mruby-range-ext"
  conf.gem core: "mruby-proc-ext"
  conf.gem core: "mruby-symbol-ext"
  conf.gem core: "mruby-random"
  conf.gem core: "mruby-object-ext"
  conf.gem core: "mruby-objectspace"
  conf.gem core: "mruby-fiber"
  conf.gem core: "mruby-enumerator"
  conf.gem core: "mruby-enum-lazy"
  conf.gem core: "mruby-toplevel-ext"
  conf.gem core: "mruby-kernel-ext"
  conf.gem core: "mruby-class-ext"
  conf.gem core: "mruby-compiler"
end
