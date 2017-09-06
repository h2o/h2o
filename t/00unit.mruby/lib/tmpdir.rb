require 'fileutils'

class Dir
  @@systmpdir = '/tmp'

  def self.tmpdir
    if ($SAFE || 0) > 0
      @@systmpdir.dup
    else
      tmp = nil
      [ENV['TMPDIR'], ENV['TMP'], ENV['TEMP'], '/tmp', '.'].each do |dir|
        next if !dir
        dir = File.expand_path(dir)
        if stat = File.stat(dir) and stat.directory? and stat.writable? and
            (!stat.world_writable? or stat.sticky?)
          tmp = dir
          break
        end rescue nil
      end
      raise ArgumentError, "could not find a temporary directory" unless tmp
      tmp
    end
  end

  def self.mktmpdir(prefix_suffix=nil, dir = nil)
    path = Tmpname.create(prefix_suffix || "d", dir) {|n| mkdir(n, 0700)}
    if block_given?
      begin
        yield path
      ensure
        stat = File.stat(File.dirname(path))
        if stat.world_writable? and !stat.sticky?
          raise ArgumentError, "parent directory is world writable but not sticky"
        end
        FileUtils.remove_entry path
      end
    else
      path
    end
  end

  module Tmpname
    INT_MAX = begin
      l = 0
      r = 1 << 64
      loop do
        m = (l + r) >> 1
        break if m == l || m == r
        if m.class == Fixnum
          l = m
        else
          r = m
        end
      end
      l
    end

    def self.tmpdir
      Dir.tmpdir
    end

    def self.make_tmpname((prefix, suffix), n)
      prefix = (String.try_convert(prefix) or
                raise ArgumentError, "unexpected prefix: #{prefix.inspect}")
      suffix &&= (String.try_convert(suffix) or
                  raise ArgumentError, "unexpected suffix: #{suffix.inspect}")
      now = Time.now
      t = sprintf('%d%02d%02d', now.year, now.month, now.day)
      pid = $$ | 0
      path = "#{prefix}#{t}-#{pid}-#{rand(INT_MAX).to_s(36)}".dup
      path << "-#{n}" if n
      path << suffix if suffix
      path
    end

    def self.create(basename, tmpdir=nil)
      if ($SAFE || 0) > 0  and tmpdir.tainted?
        tmpdir = '/tmp'
      else
        tmpdir ||= tmpdir()
      end
      n = nil
      begin
        path = File.join(tmpdir, make_tmpname(basename, n))
        yield(path, n)
      rescue Errno::EEXIST
        n ||= 0
        n += 1
        retry if !max_try or n < max_try
        raise "cannot generate temporary name using `#{basename}' under `#{tmpdir}'"
      end
      path
    end
  end
end
