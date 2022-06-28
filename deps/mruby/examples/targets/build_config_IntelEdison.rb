# Cross-compiling setup for Intel Edison (poky linux) platform
# Get SDK from here: https://software.intel.com/en-us/iot/hardware/edison/downloads
# REMEMBER to check and update the SDK root in the constant POKY_EDISON_PATH

MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'
  conf.cc.defines = %w(ENABLE_READLINE)
  conf.gembox 'default'

  #lightweight regular expression
  conf.gem :github => "pbosetti/mruby-hs-regexp", :branch => "master"

end

# Define cross build settings
MRuby::CrossBuild.new('core2-32-poky-linux') do |conf|
  toolchain :gcc

  # Mac OS X
  #
  POKY_EDISON_PATH = '/opt/poky-edison/1.7.2'

  POKY_EDISON_SYSROOT =  "#{POKY_EDISON_PATH}/sysroots/core2-32-poky-linux"
  POKY_EDISON_X86_PATH = "#{POKY_EDISON_PATH}/sysroots/i386-pokysdk-darwin"
  POKY_EDISON_BIN_PATH = "#{POKY_EDISON_X86_PATH}/usr/bin/i586-poky-linux"


  conf.cc do |cc|
    cc.command = "#{POKY_EDISON_BIN_PATH}/i586-poky-linux-gcc"
    cc.include_paths << ["#{POKY_EDISON_SYSROOT}/usr/include", "#{POKY_EDISON_X86_PATH}/usr/include"]
    cc.flags = %w(-m32 -march=core2 -mtune=core2 -msse3 -mfpmath=sse -mstackrealign -fno-omit-frame-pointer)
    cc.flags << %w(-O2 -pipe -g -feliminate-unused-debug-types)
    cc.flags << "--sysroot=#{POKY_EDISON_SYSROOT}"
    cc.compile_options = %Q[%{flags} -o "%{outfile}" -c "%{infile}"]
    cc.defines = %w(ENABLE_READLINE)
  end

  conf.cxx do |cxx|
    cxx.command = "#{POKY_EDISON_BIN_PATH}/i586-poky-linux-g++"
    cxx.include_paths = conf.cc.include_paths.dup
    cxx.include_paths << ["#{POKY_EDISON_SYSROOT}/usr/include/c++/4.9.1"]
    cxx.flags = conf.cc.flags.dup
    cxx.defines = conf.cc.defines.dup
    cxx.compile_options = conf.cc.compile_options.dup
  end

  conf.archiver do |archiver|
    archiver.command = "#{POKY_EDISON_BIN_PATH}/i586-poky-linux-ar"
    archiver.archive_options = 'rcs "%{outfile}" %{objs}'
  end

  conf.linker do |linker|
    linker.command = "#{POKY_EDISON_BIN_PATH}/i586-poky-linux-g++"
    linker.flags = %w(-m32 -march=i586)
    linker.flags << "--sysroot=#{POKY_EDISON_SYSROOT}"
    linker.flags << %w(-O1)
    linker.libraries = %w(m pthread)
  end

  #do not build executable test
  conf.build_mrbtest_lib_only

  conf.gembox 'default'

  #lightweight regular expression
  conf.gem :github => "pbosetti/mruby-hs-regexp", :branch => "master"

end
