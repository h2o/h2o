# Cross Compiling configuration for the Nintendo Switch, it requires Nintendo SDK
# Tested on windows
MRuby::CrossBuild.new('nintendo_switch_32bit') do |conf|
  conf.toolchain :clang
  NINTENDO_SDK_PATH = ENV['NINTENDO_SDK_ROOT']

  include_paths = [
    "#{NINTENDO_SDK_PATH}/Include",
    "#{NINTENDO_SDK_PATH}/Common/Configs/Targets/NX-NXFP2-a32/Include"
  ]

  conf.cc do |cc|
    cc.command = "#{NINTENDO_SDK_PATH}/Compilers/NX/bin/nx-clang++"
    cc.include_paths += include_paths
    cc.flags += ['-fpic -fno-short-enums -ffunction-sections -fdata-sections -fno-common -fno-strict-aliasing -fomit-frame-pointer -fno-vectorize -funsigned-char -O2 -g -mno-implicit-float']
    cc.defines += 'NN_SDK_BUILD_RELEASE'
  end

  conf.cxx do |cxx|
    cxx.command = "#{NINTENDO_SDK_PATH}/Compilers/NX/bin/nx-clang++"
    cxx.include_paths += include_paths
    cxx.flags += ['-fpic -fno-short-enums -ffunction-sections -fdata-sections -fno-common -fno-strict-aliasing -fomit-frame-pointer -fno-vectorize -funsigned-char -O2 -g -mno-implicit-float']
    cxx.defines += 'NN_SDK_BUILD_RELEASE'
  end

  conf.archiver do |archiver|
    archiver.command = "#{NINTENDO_SDK_PATH}/Compilers/NX/nx/armv7l/bin/llvm-ar"
  end

  conf.linker do |linker|
    linker.command = "#{NINTENDO_SDK_PATH}/Compilers/NX/nx/armv7l/bin/clang++"
    linker.libraries = []
  end

  # Add your mrbgems
end

MRuby::CrossBuild.new('nintendo_switch_64bit') do |conf|
  conf.toolchain :clang
  NINTENDO_SDK_PATH = ENV['NINTENDO_SDK_ROOT']

  include_paths = [
    "#{NINTENDO_SDK_PATH}/Include",
    "#{NINTENDO_SDK_PATH}/Common/Configs/Targets/NX-NXFP2-a64/Include"
  ]

  conf.cc do |cc|
    cc.command = "#{NINTENDO_SDK_PATH}/Compilers/NX/bin/nx-clang++"
    cc.include_paths += include_paths
    cc.flags += ['-fpic -fno-short-enums -ffunction-sections -fdata-sections -fno-common -fno-strict-aliasing -fomit-frame-pointer -fno-vectorize -funsigned-char -O2 -g -mno-implicit-float']
    cc.flags << '--target=aarch64-nintendo-nx-elf'
    cc.defines += 'NN_SDK_BUILD_RELEASE'
  end

  conf.cxx do |cxx|
    cxx.command = "#{NINTENDO_SDK_PATH}/Compilers/NX/bin/nx-clang++"
    cxx.include_paths += include_paths
    cxx.flags += ['-fpic -fno-short-enums -ffunction-sections -fdata-sections -fno-common -fno-strict-aliasing -fomit-frame-pointer -fno-vectorize -funsigned-char -O2 -g -mno-implicit-float']
    cxx.flags << '--target=aarch64-nintendo-nx-elf'
    cxx.defines += 'NN_SDK_BUILD_RELEASE'
  end

  conf.archiver do |archiver|
    archiver.command = "#{NINTENDO_SDK_PATH}/Compilers/NX/nx/aarch64/bin/llvm-ar"
  end

  conf.linker do |linker|
    linker.command = "#{NINTENDO_SDK_PATH}/Compilers/NX/nx/aarch64/bin/clang++"
    linker.libraries = []
  end

  # Add your mrbgems
end
