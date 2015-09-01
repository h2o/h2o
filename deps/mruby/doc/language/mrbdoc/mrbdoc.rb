#!/usr/bin/env ruby

$: << File.dirname(__FILE__) + '/lib'

require 'mrbdoc_analyze'
require 'mrbdoc_docu'

MRUBY_ROOT = ARGV[0]
DOC_ROOT = ARGV[1]
_WRITE_LINE_NO = ARGV[2]
STDOUT.sync = true

raise ArgumentError.new 'mruby root missing!' if MRUBY_ROOT.nil?
raise ArgumentError.new 'doc root missing!' if DOC_ROOT.nil?

if _WRITE_LINE_NO.nil?
  WRITE_LINE_NO = true
else
  case _WRITE_LINE_NO
  when 'true'
    WRITE_LINE_NO = true
  when 'false'
    WRITE_LINE_NO = false
  else
    raise ArgumentError.new 'Line no parameter has to be false or true!'
  end
end

mrbdoc = MRBDoc.new

mrbdoc.analyze_code MRUBY_ROOT do |progress|
  puts progress
end

cfg = {:print_line_no => WRITE_LINE_NO}
mrbdoc.write_documentation DOC_ROOT, cfg do |progress|
  puts progress
end
