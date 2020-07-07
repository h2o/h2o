module Kernel
  def `(cmd)
    IO.popen(cmd) { |io| io.read }
  end

  def open(file, *rest, &block)
    raise ArgumentError unless file.is_a?(String)

    if file[0] == "|"
      IO.popen(file[1..-1], *rest, &block)
    else
      File.open(file, *rest, &block)
    end
  end

  def print(*args)
    $stdout.print(*args)
  end

  def puts(*args)
    $stdout.puts(*args)
  end

  def printf(*args)
    $stdout.printf(*args)
  end

  def gets(*args)
    $stdin.gets(*args)
  end
end
