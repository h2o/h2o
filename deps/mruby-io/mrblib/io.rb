##
# IO

class IOError < StandardError; end
class EOFError < IOError; end

class IO
  SEEK_SET = 0
  SEEK_CUR = 1
  SEEK_END = 2

  BUF_SIZE = 4096

  def self.open(*args, &block)
    io = self.new(*args)

    return io unless block

    begin
      yield io
    ensure
      begin
        io.close unless io.closed?
      rescue StandardError
      end
    end
  end

  def self.popen(command, mode = 'r', &block)
    io = self._popen(command, mode)
    return io unless block

    begin
      yield io
    ensure
      begin
        io.close unless io.closed?
      rescue IOError
        # nothing
      end
    end
  end


  def self.read(path, length=nil, offset=nil, opt=nil)
    if not opt.nil?        # 4 arguments
      offset ||= 0
    elsif not offset.nil?  # 3 arguments
      if offset.is_a? Hash
        opt = offset
        offset = 0
      else
        opt = {}
      end
    elsif not length.nil?  # 2 arguments
      if length.is_a? Hash
        opt = length
        offset = 0
        length = nil
      else
        offset = 0
        opt = {}
      end
    else                   # only 1 argument
      opt = {}
      offset = 0
      length = nil
    end

    str = ""
    fd = -1
    io = nil
    begin
      if path[0] == "|"
        io = IO.popen(path[1..-1], (opt[:mode] || "r"))
      else
        fd = IO.sysopen(path)
        io = IO.open(fd, opt[:mode] || "r")
      end
      io.seek(offset) if offset > 0
      str = io.read(length)
    ensure
      if io
        io.close
      elsif fd != -1
        IO._sysclose(fd)
      end
    end
    str
  end

  def flush
    # mruby-io always writes immediately (no output buffer).
    raise IOError, "closed stream" if self.closed?
    self
  end

  def write(string)
    str = string.is_a?(String) ? string : string.to_s
    return str.size unless str.size > 0

    len = syswrite(str)
    if len != -1
      @pos += len
      return len
    end

    raise IOError
  end

  def eof?
    return true if @buf && @buf.size > 0

    ret = false
    char = ''

    begin
      char = sysread(1)
    rescue EOFError => e
      ret = true
    ensure
      _ungets(char)
    end

    ret
  end
  alias_method :eof, :eof?

  def pos
    raise IOError if closed?
    @pos
  end
  alias_method :tell, :pos

  def pos=(i)
    seek(i, SEEK_SET)
  end

  def seek(i, whence = SEEK_SET)
    raise IOError if closed?
    @pos = sysseek(i, whence)
    @buf = ''
    0
  end

  def _read_buf
    return @buf if @buf && @buf.size > 0
    @buf = sysread(BUF_SIZE)
  end

  def _ungets(substr)
    raise TypeError.new "expect String, got #{substr.class}" unless substr.is_a?(String)
    raise IOError if @pos == 0 || @pos.nil?
    @pos -= substr.size
    if @buf.empty?
      @buf = substr
    else
      @buf = substr + @buf
    end
    nil
  end

  def ungetc(char)
    raise IOError if @pos == 0 || @pos.nil?
    _ungets(char)
    nil
  end

  def read(length = nil)
    unless length.nil?
      unless length.is_a? Fixnum
        raise TypeError.new "can't convert #{length.class} into Integer"
      end
      if length < 0
        raise ArgumentError.new "negative length: #{length} given"
      end
      if length == 0
        return ""   # easy case
      end
    end

    array = []
    start_pos = @pos
    while 1
      begin
        _read_buf
      rescue EOFError => e
        array = nil if array.empty? and (not length.nil?) and length != 0
        break
      end

      if length && (@pos - start_pos + @buf.size) >= length
        len = length - (@pos - start_pos)
        array.push @buf[0, len]
        @pos += len
        @buf = @buf[len, @buf.size - len]
        break
      else
        array.push @buf
        @pos += @buf.size
        @buf = ''
      end
    end

    array && array.join
  end

  def readline(arg = $/, limit = nil)
    case arg
    when String
      rs = arg
    when Fixnum
      rs = $/
      limit = arg
    else
      raise ArgumentError
    end

    if rs.nil?
      return read
    end

    if rs == ""
      rs = $/ + $/
    end

    array = []
    start_pos = @pos
    while 1
      begin
        _read_buf
      rescue EOFError => e
        array = nil if array.empty?
        break
      end

      if limit && (@pos - start_pos + @buf.size) >= limit
        len = limit - (@pos - start_pos)
        array.push @buf[0, len]
        @pos += len
        @buf = @buf[len, @buf.size - len]
        break
      elsif idx = @buf.index(rs)
        len = idx + rs.size
        array.push @buf[0, len]
        @pos += len
        @buf = @buf[len, @buf.size - len]
        break
      else
        array.push @buf
        @pos += @buf.size
        @buf = ''
      end
    end

    raise EOFError.new "end of file reached" if array.nil?

    array.join
  end

  def gets(*args)
    begin
      readline(*args)
    rescue EOFError => e
      nil
    end
  end

  def readchar
    _read_buf
    c = @buf[0]
    @buf = @buf[1, @buf.size]
    @pos += 1
    c
  end

  def getc
    begin
      readchar
    rescue EOFError => e
      nil
    end
  end

  # 15.2.20.5.3
  def each(&block)
    while line = self.gets
      block.call(line)
    end
    self
  end

  # 15.2.20.5.4
  def each_byte(&block)
    while char = self.getc
      block.call(char)
    end
    self
  end

  # 15.2.20.5.5
  alias each_line each

  alias each_char each_byte

  def readlines
    ary = []
    while (line = gets)
      ary << line
    end
    ary
  end

  def puts(*args)
    i = 0
    len = args.size
    while i < len
      s = args[i].to_s
      write s
      write "\n" if (s[-1] != "\n")
      i += 1
    end
    write "\n" if len == 0
    nil
  end

  def print(*args)
    i = 0
    len = args.size
    while i < len
      write args[i].to_s
      i += 1
    end
  end

  def printf(*args)
    write sprintf(*args)
    nil
  end

  alias_method :to_i, :fileno
end

STDIN  = IO.open(0, "r")
STDOUT = IO.open(1, "w")
STDERR = IO.open(2, "w")

$stdin  = STDIN
$stdout = STDOUT
$stderr = STDERR

module Kernel
  def print(*args)
    STDOUT.print(*args)
  end

  def puts(*args)
    STDOUT.puts(*args)
  end

  def printf(*args)
    STDOUT.printf(*args)
  end

  def gets(*args)
    STDIN.gets(*args)
  end

  def getc(*args)
    STDIN.getc(*args)
  end
end
