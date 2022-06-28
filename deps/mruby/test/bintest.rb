$:.unshift File.dirname(File.dirname(File.expand_path(__FILE__)))
require 'test/assert.rb'

GEMNAME = ""

def cmd(s)
  case RbConfig::CONFIG['host_os']
  when /mswin(?!ce)|mingw|bccwin/
    "bin\\#{s}.exe"
  else
    "bin/#{s}"
  end
end

def shellquote(s)
  case RbConfig::CONFIG['host_os']
  when /mswin(?!ce)|mingw|bccwin/
    "\"#{s}\""
  else
    "'#{s}'"
  end
end

print "bintest - Command Binary Test\n\n"

ARGV.each do |gem|
  case gem
  when '-v'; $mrbtest_verbose = true
  end

  case RbConfig::CONFIG['host_os']
  when /mswin(?!ce)|mingw|bccwin/
    gem = gem.gsub('\\', '/')
  end

  Dir["#{gem}/bintest/**/*.rb"].each do |file|
    GEMNAME.replace(File.basename(gem))
    load file
  end
end

exit report
