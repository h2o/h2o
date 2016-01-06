require 'mkmf'
require 'rake/clean'

# patch for old mkmf bug
if RUBY_VERSION <= "1.9.3"
  def try_link(src, opt="", *opts, &b)
    try_link0(src, opt, *opts, &b)
  ensure
    rm_f ["conftest*", "c0x32*"]
  end
end
# patch end

file_stat_dir = File.dirname(__FILE__)
extconf = "#{file_stat_dir}/src/extconf.h"

file extconf => ["#{file_stat_dir}/src/file-stat.c"] do |t|
  File.unlink(t.name) if File.exist?(t.name)

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

  create_header t.name
end

CLOBBER << extconf

MRuby::Gem::Specification.new('mruby-file-stat') do |spec|
  spec.license = 'MIT'
  spec.author  = 'ksss <co000ri@gmail.com>'
  spec.add_dependency('mruby-time')

  Rake::Task[extconf].invoke
end
