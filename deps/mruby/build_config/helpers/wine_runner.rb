#!/usr/bin/env ruby

# Wrapper for running tests for cross-compiled Windows builds in Wine.

require 'open3'

DOSROOT = 'z:'

# Rewrite test output to replace DOS-isms with Unix-isms.
def clean(output, stderr = false)
  ends_with_newline = !!(output =~ /\n$/)
  executable = ARGV[0].gsub(/\.exe\z/i, '')

  # Fix line-ends
  output = output.gsub(/\r\n/, "\n")

  # Strip out Wine messages


  results = output.split(/\n/).map do |line|
    # Fix file paths
    if line =~ /#{DOSROOT}\\/i
      line.gsub!(/#{DOSROOT}([^:]*)/i) { |path|
        path.gsub!(/^#{DOSROOT}/i, '')
        path.gsub!(%r{\\}, '/')
        path
      }
    end

    # strip '.exe' off the end of the executable's name if needed
    line.gsub!(/(#{Regexp.escape executable})\.exe/i, '\1')

    line
  end

  result_text = results.join("\n")
  result_text += "\n" if ends_with_newline
  return result_text
end


def main
  if ARGV.empty? || ARGV[0] =~ /^- (-?) (\?|help|h) $/x
    puts "#{$0} <command-line>"
    exit 0
  end

  # For simplicity, just read all of stdin into memory and pass that
  # as an argument when invoking wine.  (Skipped if STDIN was not
  # redirected.)
  if !STDIN.tty?
    input = STDIN.read
  else
    input = ""
  end

  # Disable all Wine messages so they don't interfere with the output
  ENV['WINEDEBUG'] = 'err-all,warn-all,fixme-all,trace-all'

  # Run the program in wine and capture the output
  output, errormsg, status = Open3.capture3('wine', *ARGV, :stdin_data => input)

  # Clean and print the results.
  STDOUT.write clean(output)
  STDERR.write clean(errormsg)

  exit(status.exitstatus)
end


main()
