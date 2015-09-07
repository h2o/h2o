MRuby::Build.new do |conf|
  # load specific toolchain settings

  # Gets set by the VS command prompts.
  if ENV['MRUBY_TOOLCHAIN']
    toolchain ENV['MRUBY_TOOLCHAIN']
  elsif ENV['VisualStudioVersion'] || ENV['VSINSTALLDIR']
    toolchain :visualcpp
  else
    toolchain :gcc
  end

  enable_debug

  # use mrbgems
  Dir.glob("../mruby-*/mrbgem.rake") do |x|
    g = File.basename File.dirname x
    conf.gem "../deps/#{g}"
  end

  # include all the core GEMs
  conf.gembox 'full-core'
end
