module Kernel
  def self.`(cmd)
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
end
