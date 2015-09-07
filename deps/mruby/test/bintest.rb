$:.unshift File.dirname(File.dirname(File.expand_path(__FILE__)))
require 'test/assert.rb'

ARGV.each do |gem|
  Dir["#{gem}/bintest/**/*.rb"].each do |file|
    load file
  end
end

load 'test/report.rb'
