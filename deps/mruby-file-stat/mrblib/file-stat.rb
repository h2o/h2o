class File
  class Stat
    include Comparable

    def <=>(other)
      if other.kind_of?(self.class)
        self.mtime <=> other.mtime
      else
        nil
      end
    end

    def inspect
      _dev = dev
      _dev = "0x#{_dev.to_s(16)}" if _dev.kind_of?(Fixnum)
      _mode = mode
      _mode = "0#{_mode.to_s(8)}" if _mode.kind_of?(Fixnum)
      _rdev = rdev
      _rdev = "0x#{_rdev.to_s(16)}" if _rdev.kind_of?(Fixnum)

      stats = {
        'dev' => _dev,
        'ino' => ino,
        'mode' => _mode,
        'nlink' => nlink,
        'uid' => uid,
        'gid' => gid,
        'rdev' => _rdev,
        'size' => size,
        'blksize' => blksize,
        'blocks' => blocks,
        'atime' => atime,
        'mtime' => mtime,
        'ctime' => ctime,
      }
      if respond_to? :birthtime
        stats['birthtime'] = birthtime
      end

      "#<#{self.class.to_s} #{stats.map{|k, v| "#{k}=#{v}"}.join(', ')}>"
    end

    def size?
      s = size
      s == 0 ? nil : s
    end

    def zero?
      size == 0
    end
  end
end
