#!/usr/bin/env ruby

require 'pty'

c_dir = File.dirname(__FILE__)
MRUBY_ROOT = File.expand_path("#{c_dir}/../..")
DOC_DIR = File.expand_path(c_dir)

cmd = "ruby #{DOC_DIR}/mrbdoc/mrbdoc.rb #{MRUBY_ROOT} #{DOC_DIR} false"
IO.popen(cmd, "r+") do |io|
  io.close_write
  while line = io.gets
    puts line
  end
end
