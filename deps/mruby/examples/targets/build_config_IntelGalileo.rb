MRuby::Build.new do |conf|

  # Gets set by the VS command prompts.
  if ENV['VisualStudioVersion'] || ENV['VSINSTALLDIR']
    toolchain :visualcpp
  else
    toolchain :gcc
  end

  enable_debug

  # include the default GEMs
  conf.gembox 'default'

end


# Cross Compiling configuration for Intel Galileo on Arduino environment
# http://arduino.cc/en/ArduinoCertified/IntelGalileo
#
# Requires Arduino IDE for Intel Galileo
MRuby::CrossBuild.new("Galileo") do |conf|
  toolchain :gcc

  # Mac OS X
  # Assume you renamed Arduino.app to Arduino_Galileo.app
  GALILEO_ARDUINO_PATH = '/Applications/Arduino_Galileo.app/Contents/Resources/Java'
  # GNU Linux
  #ARDUINO_GALILEO_PATH = '/opt/arduino'

  GALILEO_BIN_PATH = "#{GALILEO_ARDUINO_PATH}/hardware/tools/x86/i386-pokysdk-darwin/usr/bin/i586-poky-linux-uclibc"
  GALILEO_SYSROOT =  "#{GALILEO_ARDUINO_PATH}/hardware/tools/x86/i586-poky-linux-uclibc"
  GALILEO_X86_PATH = "#{GALILEO_ARDUINO_PATH}/hardware/arduino/x86"


  conf.cc do |cc|
    cc.command = "#{GALILEO_BIN_PATH}/i586-poky-linux-uclibc-gcc"
    cc.include_paths << ["#{GALILEO_X86_PATH}/cores/arduino", "#{GALILEO_X86_PATH}/variants/galileo_fab_d"]
    cc.flags = %w(-m32 -march=i586 -c -g -Os -w
              -ffunction-sections -fdata-sections -MMD -DARDUINO=153)
    cc.flags << "--sysroot=#{GALILEO_SYSROOT}"
    cc.compile_options = %Q[%{flags} -o "%{outfile}" -c "%{infile}"]
  end

  conf.cxx do |cxx|
    cxx.command = "#{GALILEO_BIN_PATH}/i586-poky-linux-uclibc-g++"
    cxx.include_paths = conf.cc.include_paths.dup
    cxx.include_paths << "#{GALILEO_ARDUINO_PATH}/hardware/tools/x86/i586-poky-linux-uclibc/usr/include/c++"
    cxx.include_paths << "#{GALILEO_ARDUINO_PATH}/hardware/tools/x86/i586-poky-linux-uclibc/usr/include/c++/i586-poky-linux-uclibc"
    cxx.flags = conf.cc.flags.dup
    cxx.defines = conf.cc.defines.dup
    cxx.compile_options = conf.cc.compile_options.dup
  end

  conf.archiver do |archiver|
    archiver.command = "#{GALILEO_BIN_PATH}/i586-poky-linux-uclibc-ar"
    archiver.archive_options = 'rcs "%{outfile}" %{objs}'
  end

  conf.linker do |linker|
    linker.command = "#{GALILEO_BIN_PATH}/i586-poky-linux-uclibc-g++"
    linker.flags = %w(-m32 -march=i586)
    linker.flags << "--sysroot=#{GALILEO_SYSROOT}"
    linker.flags << %w(-Os -Wl,--gc-sections)
    linker.libraries = %w(m pthread)
  end

  #no executables
  conf.bins = []

  #do not build executable test
  conf.build_mrbtest_lib_only

  #official mrbgems
  conf.gem :core => "mruby-sprintf"
  conf.gem :core => "mruby-print"
  conf.gem :core => "mruby-math"
  conf.gem :core => "mruby-time"
  conf.gem :core => "mruby-struct"
  conf.gem :core => "mruby-enum-ext"
  conf.gem :core => "mruby-string-ext"
  conf.gem :core => "mruby-numeric-ext"
  conf.gem :core => "mruby-array-ext"
  conf.gem :core => "mruby-hash-ext"
  conf.gem :core => "mruby-range-ext"
  conf.gem :core => "mruby-proc-ext"
  conf.gem :core => "mruby-symbol-ext"
  conf.gem :core => "mruby-random"
  conf.gem :core => "mruby-object-ext"
  conf.gem :core => "mruby-objectspace"
  conf.gem :core => "mruby-fiber"
  conf.gem :core => "mruby-toplevel-ext"

  #lightweigh regular expression
  conf.gem :github => "masamitsu-murase/mruby-hs-regexp", :branch => "master"

  #Arduino API
  #conf.gem :github =>"kyab/mruby-arduino", :branch => "master" do |g|
  #  g.cxx.include_paths << "#{GALILEO_X86_PATH}/libraries/Wire"
  #  g.cxx.include_paths << "#{GALILEO_X86_PATH}/libraries/Servo"

    #enable unsupported Servo class
  #  g.cxx.defines << "MRUBY_ARDUINO_GALILEO_ENABLE_SERVO"
  #end

end
