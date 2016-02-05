require 'mkmf'

# patch for old mkmf bug
if RUBY_VERSION <= "1.9.3"
  def try_link(src, opt="", *opts, &b)
    try_link0(src, opt, *opts, &b)
  ensure
    rm_f ["conftest*", "c0x32*"]
  end
end
# patch end

build_extconf = lambda do |fn|
  return if File.exist?(fn)

  # TODO
  # if open this block
  # raise error: redefinition of 'struct timespec'
  # in windows
  if RUBY_PLATFORM !~ /mingw|mswin/
    have_struct_member "struct stat", "st_birthtimespec", "sys/stat.h"
    have_struct_member "struct stat", "st_blksize", "sys/stat.h"
    have_struct_member "struct stat", "st_blocks", "sys/stat.h"

    have_func "lstat", "sys/stat.h"
    have_func "getgroups", "unistd.h"
  end

  create_header fn
end

MRuby::Gem::Specification.new('mruby-file-stat') do |spec|
  spec.license = 'MIT'
  spec.author  = 'ksss <co000ri@gmail.com>'
  spec.add_dependency('mruby-time')

  FileUtils.mkdir_p build_dir
  build_extconf["#{build_dir}/extconf.h"]
  cc.include_paths << build_dir
end
