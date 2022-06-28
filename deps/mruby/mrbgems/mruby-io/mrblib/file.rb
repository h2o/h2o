class File < IO
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
    return "" if names.empty?

    names.map! do |name|
      case name
      when String
        name
      when Array
        if names == name
          raise ArgumentError, "recursive array"
        end
        join(*name)
      else
        raise TypeError, "no implicit conversion of #{name.class} into String"
      end
    end

    return names[0] if names.size == 1

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

  def self._concat_path(path, base_path)
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
      expanded_path = _concat_path(base_path, _getwd)
      expanded_path += "/" + path
    end

    expanded_path
  end

  def self.expand_path(path, default_dir = '.')
    expanded_path = _concat_path(path, default_dir)
    drive_prefix = ""
    if File::ALT_SEPARATOR && expanded_path.size > 2 &&
        ("A".."Z").include?(expanded_path[0].upcase) && expanded_path[1] == ":"
      drive_prefix = expanded_path[0, 2]
      expanded_path = expanded_path[2, expanded_path.size]
    end
    expand_path_array = []
    if File::ALT_SEPARATOR && expanded_path.include?(File::ALT_SEPARATOR)
      expanded_path.gsub!(File::ALT_SEPARATOR, '/')
    end
    while expanded_path.include?('//')
      expanded_path = expanded_path.gsub('//', '/')
    end

    if expanded_path != "/"
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

      expanded_path = expand_path_array.join("/")
      if expanded_path.empty?
        expanded_path = '/'
      end
    end
    if drive_prefix.empty?
      expanded_path
    else
      drive_prefix + expanded_path.gsub("/", File::ALT_SEPARATOR)
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

  def self.path(filename)
    if filename.kind_of?(String)
      filename
    elsif filename.respond_to?(:to_path)
      filename.to_path
    else
      raise TypeError, "no implicit conversion of #{filename.class} into String"
    end
  end
end
