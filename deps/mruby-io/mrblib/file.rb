class File < IO
  include Enumerable

  class FileError < Exception; end
  class NoFileError < FileError; end
  class UnableToStat < FileError; end
  class PermissionError < FileError; end

  attr_accessor :path

  def initialize(fd_or_path, mode = "r", perm = 0666)
    if fd_or_path.kind_of? Fixnum
      super(fd_or_path, mode)
    else
      @path = fd_or_path
      fd = IO.sysopen(@path, mode, perm)
      super(fd, mode)
    end
  end

  def self.join(*names)
    if names.size == 0
      ""
    elsif names.size == 1
      names[0]
    else
      if names[0][-1] == File::SEPARATOR
        s = names[0][0..-2]
      else
        s = names[0].dup
      end
      (1..names.size-2).each { |i|
        t = names[i]
        if t[0] == File::SEPARATOR and t[-1] == File::SEPARATOR
          t = t[1..-2]
        elsif t[0] == File::SEPARATOR
          t = t[1..-1]
        elsif t[-1] == File::SEPARATOR
          t = t[0..-2]
        end
        s += File::SEPARATOR + t if t != ""
      }
      if names[-1][0] == File::SEPARATOR
        s += File::SEPARATOR + names[-1][1..-1]
      else
        s += File::SEPARATOR + names[-1]
      end
      s
    end
  end

  def self.expand_path(path, default_dir = '.')
    def concat_path(path, base_path)
      if path[0] == "/" || path[1] == ':' # Windows root!
        expanded_path = path
      elsif path[0] == "~"
        if (path[1] == "/" || path[1] == nil)
          dir = path[1, path.size]
          home_dir = _gethome

          unless home_dir
            raise ArgumentError, "couldn't find HOME environment -- expanding '~'"
          end

          expanded_path = home_dir
          expanded_path += dir if dir
          expanded_path += "/"
        else
          splitted_path = path.split("/")
          user = splitted_path[0][1, splitted_path[0].size]
          dir = "/" + splitted_path[1, splitted_path.size].join("/")

          home_dir = _gethome(user)

          unless home_dir
            raise ArgumentError, "user #{user} doesn't exist"
          end

          expanded_path = home_dir
          expanded_path += dir if dir
          expanded_path += "/"
        end
      else
        expanded_path = concat_path(base_path, _getwd)
        expanded_path += "/" + path
      end

      expanded_path
    end

    expanded_path = concat_path(path, default_dir)
    expand_path_array = []
    while expanded_path.include?('//')
      expanded_path = expanded_path.gsub('//', '/')
    end

    if expanded_path == "/"
      expanded_path
    else
      expanded_path.split('/').each do |path_token|
        if path_token == '..'
          if expand_path_array.size > 1
            expand_path_array.pop
          end
        elsif path_token == '.'
          # nothing to do.
        else
          expand_path_array << path_token
        end
      end

      expand_path = expand_path_array.join("/")
      expand_path.empty? ? '/' : expand_path
    end
  end

  def self.foreach(file)
    if block_given?
      self.open(file) do |f|
        f.each {|l| yield l}
      end
    else
      return self.new(file)
    end
  end

  def self.directory?(file)
    FileTest.directory?(file)
  end

  def self.exist?(file)
    FileTest.exist?(file)
  end

  def self.exists?(file)
    FileTest.exists?(file)
  end

  def self.file?(file)
    FileTest.file?(file)
  end

  def self.pipe?(file)
    FileTest.pipe?(file)
  end

  def self.size(file)
    FileTest.size(file)
  end

  def self.size?(file)
    FileTest.size?(file)
  end

  def self.socket?(file)
    FileTest.socket?(file)
  end

  def self.symlink?(file)
    FileTest.symlink?(file)
  end

  def self.zero?(file)
    FileTest.zero?(file)
  end

  def self.extname(filename)
    fname = self.basename(filename)
    return '' if fname[0] == '.' || fname.index('.').nil?
    ext = fname.split('.').last
    ext.empty? ? '' : ".#{ext}"
  end
end
