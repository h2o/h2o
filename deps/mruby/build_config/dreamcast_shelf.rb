# Cross Compiling configuration for the Sega Dreamcast
# https://dreamcast.wiki/Using_Ruby_for_Sega_Dreamcast_development
#
# Requires KallistiOS (KOS)
# http://gamedev.allusion.net/softprj/kos/
#
# Tested on GNU/Linux, macOS and Windows (through MinGW-w64/MSYS2, Cygwin and DreamSDK).
# DreamSDK is based on MinGW/MSYS: https://dreamsdk.org/
#
# Input this command on the directory where mruby is installed:
#   make MRUBY_CONFIG=dreamcast_shelf
#
MRuby::CrossBuild.new("dreamcast") do |conf|
  toolchain :gcc

  # Support for DreamSDK (based on MinGW/MSYS)
  # To compile mruby with DreamSDK, RubyInstaller for Windows should be installed
  DREAMSDK_HOME = ENV["DREAMSDK_HOME"]
  MSYS_ROOT = !(DREAMSDK_HOME.nil? || DREAMSDK_HOME.empty?) ? "#{DREAMSDK_HOME}/msys/1.0" : ""

  # Setting paths
  DREAMCAST_PATH = "#{MSYS_ROOT}/opt/toolchains/dc"
  KOS_PATH = "#{DREAMCAST_PATH}/kos"
  BIN_PATH = "#{DREAMCAST_PATH}/sh-elf/bin"

  # C compiler
  # Flags were extracted from KallistiOS environment files
  conf.cc do |cc|
    cc.command = "#{BIN_PATH}/sh-elf-gcc"
    cc.include_paths << ["#{KOS_PATH}/include", "#{KOS_PATH}/kernel/arch/dreamcast/include", "#{KOS_PATH}/addons/include", "#{KOS_PATH}/../kos-ports/include"]
    cc.flags << ["-O2", "-fomit-frame-pointer", "-ml", "-m4-single-only", "-ffunction-sections", "-fdata-sections", "-Wall", "-g", "-fno-builtin", "-ml", "-m4-single-only", "-Wl,-Ttext=0x8c010000", "-Wl,--gc-sections", "-T#{KOS_PATH}/utils/ldscripts/shlelf.xc", "-nodefaultlibs"]
    cc.compile_options = %Q[%{flags} -o "%{outfile}" -c "%{infile}"]
    cc.defines << %w(_arch_dreamcast)
    cc.defines << %w(_arch_sub_pristine)
  end

  # C++ compiler
  conf.cxx do |cxx|
    cxx.command = conf.cc.command.dup
    cxx.include_paths = conf.cc.include_paths.dup
    cxx.flags = conf.cc.flags.dup
    cxx.flags << %w(-fno-rtti -fno-exceptions)
    cxx.defines = conf.cc.defines.dup
    cxx.compile_options = conf.cc.compile_options.dup
  end

  # Linker
  # There is an issue when making the mruby library with KallistiOS:
  # 'newlib_kill.o' and 'newlib_getpid.o' aren't found so they are explicitly
  # specified here at least for now.
  conf.linker do |linker|
    linker.command="#{BIN_PATH}/sh-elf-gcc"
    linker.flags << ["#{MSYS_ROOT}/opt/toolchains/dc/kos/kernel/build/newlib_kill.o", "#{MSYS_ROOT}/opt/toolchains/dc/kos/kernel/build/newlib_getpid.o", "-Wl,--start-group -lkallisti -lc -lgcc -Wl,--end-group"]
    linker.library_paths << ["#{KOS_PATH}/lib/dreamcast", "#{KOS_PATH}/addons/lib/dreamcast", "#{KOS_PATH}/../kos-ports/lib"]
  end

  # Archiver
  conf.archiver do |archiver|
    archiver.command = "#{BIN_PATH}/sh-elf-ar"
    archiver.archive_options = 'rcs "%{outfile}" %{objs}'
  end

  # No executables
  conf.bins = []

  # Do not build executable test
  conf.build_mrbtest_lib_only

  # Disable C++ exception
  conf.disable_cxx_exception

  # Gems from core
  # Some Gems are incompatible and were disabled.

  conf.gem :core => "mruby-array-ext"
  conf.gem :core => "mruby-binding"
  conf.gem :core => "mruby-catch"
  conf.gem :core => "mruby-class-ext"
  conf.gem :core => "mruby-cmath"
  conf.gem :core => "mruby-compar-ext"
  conf.gem :core => "mruby-compiler"
  conf.gem :core => "mruby-complex"
  conf.gem :core => "mruby-enum-chain"
  conf.gem :core => "mruby-enum-ext"
  conf.gem :core => "mruby-enum-lazy"
  conf.gem :core => "mruby-enumerator"
  conf.gem :core => "mruby-error"
  conf.gem :core => "mruby-eval"
  conf.gem :core => "mruby-exit"
  conf.gem :core => "mruby-fiber"
  conf.gem :core => "mruby-hash-ext"
#  conf.gem :core => "mruby-io"
  conf.gem :core => "mruby-kernel-ext"
  conf.gem :core => "mruby-math"
  conf.gem :core => "mruby-metaprog"
  conf.gem :core => "mruby-method"
  conf.gem :core => "mruby-numeric-ext"
  conf.gem :core => "mruby-object-ext"
  conf.gem :core => "mruby-objectspace"
  conf.gem :core => "mruby-os-memsize"
  conf.gem :core => "mruby-pack"
  conf.gem :core => "mruby-print"
  conf.gem :core => "mruby-proc-binding"
  conf.gem :core => "mruby-proc-ext"
  conf.gem :core => "mruby-random"
  conf.gem :core => "mruby-range-ext"
  conf.gem :core => "mruby-rational"
  conf.gem :core => "mruby-sleep"
#  conf.gem :core => "mruby-socket"
  conf.gem :core => "mruby-sprintf"
  conf.gem :core => "mruby-string-ext"
  conf.gem :core => "mruby-struct"
  conf.gem :core => "mruby-symbol-ext"
#  conf.gem :core => "mruby-test"
#  conf.gem :core => "mruby-time"
  conf.gem :core => "mruby-toplevel-ext"
end
