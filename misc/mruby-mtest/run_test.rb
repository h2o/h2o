#!/usr/bin/env ruby
#
# mrbgems test runner
#

if __FILE__ == $0
  repository, dir = 'https://github.com/mruby/mruby.git', 'tmp/mruby'
  build_args = ARGV
  build_args = ['all', 'test']  if build_args.nil? or build_args.empty?

  Dir.mkdir 'tmp'  unless File.exist?('tmp')
  unless File.exist?(dir)
    system "git clone #{repository} #{dir}"
  end

  exit system(%Q[cd #{dir}; MRUBY_CONFIG=#{File.expand_path __FILE__} ruby minirake #{build_args.join(' ')}])
end

MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'

  conf.gem File.expand_path(File.dirname(__FILE__))
  conf.gem :core => 'mruby-time'
  conf.gem :github => 'iij/mruby-io'
end
