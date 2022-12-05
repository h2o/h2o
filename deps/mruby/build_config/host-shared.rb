MRuby::Build.new do |conf|
  # load specific toolchain settings

  # Gets set by the VS command prompts.
  if ENV['VisualStudioVersion'] || ENV['VSINSTALLDIR']
    toolchain :visualcpp
  else
    toolchain :gcc
  end

  # include the GEM box
  conf.gembox 'default'

  # C compiler settings
  conf.cc do |cc|
    cc.flags = '-fPIC'
  end

  conf.archiver do |archiver|
    archiver.command = 'gcc'
    archiver.archive_options = '-shared -o %{outfile} %{objs}'
  end

  # file extensions
  conf.exts do |exts|
    exts.library = '.so'
  end

  # file separator
  # conf.file_separator = '/'

  # Turn on `enable_debug` for better debugging
  conf.enable_debug
  conf.enable_bintest
  conf.enable_test
end
