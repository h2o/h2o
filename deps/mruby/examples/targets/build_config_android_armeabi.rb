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

# Requires Android NDK r13 or later.
MRuby::CrossBuild.new('android-armeabi') do |conf|
  params = { 
    :arch => 'armeabi', 
    :platform => 'android-24',
    :toolchain => :clang,
  }
  toolchain :android, params

  conf.gembox 'default'
end
