# Requires Android NDK r13 or later.
MRuby::CrossBuild.new('android-arm64-v8a') do |conf|
  params = {
    :arch => 'arm64-v8a',
    :platform => 'android-24',
    :toolchain => :clang,
  }
  toolchain :android, params

  conf.gembox 'default'
end
