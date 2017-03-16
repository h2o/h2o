class FileStatTest
  class << self
    def chmod(mode, path)
      system("chmod #{mode} #{path}")
      yield
    ensure
      system("chmod 644 #{path}")
    end
  end
end

assert 'File::Stat.new' do
  assert_kind_of File::Stat, File::Stat.new('README.md')
  assert_raise(RuntimeError){ File::Stat.new('unknown.file') }
end

assert 'File.stat' do
  assert_kind_of File::Stat, File.stat('README.md')
end

assert 'File.lstat' do
  assert_kind_of File::Stat, File.lstat('README.md')
end

assert 'File::Stat#initialize_copy' do
  orig = File::Stat.new('README.md')
  copy = orig.dup
  assert_equal orig.inspect, copy.inspect
end

assert 'File::Stat#<=>' do
  stat1 = File::Stat.new('README.md')
  stat2 = File::Stat.new('README.md')
  assert_equal 0, stat1.<=>(stat2)
  assert_equal nil, stat1.<=>(1)
  assert_raise(ArgumentError) { stat1 < 1 }
end

assert 'File::Stat#dev' do
  stat = File::Stat.new('README.md')
  assert_kind_of Fixnum, stat.dev
end

assert 'File::Stat#dev_major' do
  stat = File::Stat.new('README.md')
  if stat.dev_major
    assert_equal Fixnum, stat.dev_major.class
  else
    assert_nil stat.dev_major  ## not supported
  end
end

assert 'File::Stat#dev_minor' do
  stat = File::Stat.new('README.md')
  if stat.dev_minor
    assert_equal Fixnum, stat.dev_minor.class
  else
    assert_nil stat.dev_minor  ## not supported
  end
end

assert 'File::Stat#ino' do
  stat = File::Stat.new('README.md')
  assert_kind_of Numeric, stat.ino
end

assert 'File::Stat#mode' do
  stat = File::Stat.new('README.md')
  assert_kind_of Fixnum, stat.mode
end

assert 'File::Stat#nlink' do
  stat = File::Stat.new('README.md')
  assert_kind_of Fixnum, stat.nlink
end

assert 'File::Stat#uid' do
  stat = File::Stat.new('README.md')
  assert_kind_of Numeric, stat.uid
end

assert 'File::Stat#gid' do
  stat = File::Stat.new('README.md')
  assert_kind_of Numeric, stat.gid
end

assert 'File::Stat#rdev' do
  stat = File::Stat.new('README.md')
  assert_kind_of Fixnum, stat.rdev
end

assert 'File::Stat#rdev_major' do
  stat = File::Stat.new('README.md')
  if stat.rdev_major
    assert_equal Fixnum, stat.rdev_major.class
  else
    assert_nil stat.rdev_major  ## not supported
  end
end

assert 'File::Stat#rdev_minor' do
  stat = File::Stat.new('README.md')
  if stat.rdev_minor
    assert_equal Fixnum, stat.rdev_minor.class
  else
    assert_nil stat.rdev_minor  ## not supported
  end
end

assert 'File::Stat#blocks' do
  stat = File::Stat.new('README.md')
  blocks = stat.blocks
  skip "This system not support `struct stat.st_blocks`" if blocks.nil?

  assert_kind_of Integer, blocks
end

assert 'File::Stat#atime' do
  stat = File::Stat.new('README.md')
  assert_kind_of Time, stat.atime
end

assert 'File::Stat#mtime' do
  stat = File::Stat.new('README.md')
  assert_kind_of Time, stat.mtime
end

assert 'File::Stat#ctime' do
  stat = File::Stat.new('README.md')
  assert_kind_of Time, stat.ctime
end

assert 'File::Stat#birthtime' do
  stat = File::Stat.new('README.md')
  begin
    assert_kind_of Time, stat.birthtime
  rescue NameError
    skip 'This system not support `struct stat.birthtimespec`'
  end
end

assert 'File::Stat#size' do
  stat = File::Stat.new('README.md')
  assert_true 0 < stat.size
end

assert 'File::Stat#blksize' do
  stat = File::Stat.new('README.md')
  blksize = stat.blksize
  skip "This system not support `struct stat.st_blksize`" if blksize.nil?

  assert_kind_of Integer, blksize
end

assert 'File::Stat#inspect' do
  stat = File::Stat.new('README.md')
  %w(dev ino mode nlink uid gid size blksize blocks atime mtime ctime).all? do |name|
    assert_include stat.inspect, name
  end
end

assert 'File::Stat#ftype' do
  stat = File::Stat.new('README.md')
  assert_equal "file", stat.ftype

  stat = File::Stat.new('bin')
  assert_equal "directory", stat.ftype
end

assert 'File::Stat#directory?' do
  stat = File::Stat.new('README.md')
  assert_false stat.directory?

  stat = File::Stat.new('bin')
  assert_true stat.directory?
end

assert 'File::Stat#readable?' do
  skip "when windows" if FileStatTest.win?

  dir = __FILE__[0..-18] # 18 = /test/file-stat.rb
  FileStatTest.chmod("+r-w-x", "#{dir}/test/readable") do
    assert_true File::Stat.new("#{dir}/test/readable").readable?
  end
  FileStatTest.chmod("-r+w-x", "#{dir}/test/writable") do
    assert_false File::Stat.new("#{dir}/test/writable").readable?
  end
  FileStatTest.chmod("-r-w+x", "#{dir}/test/executable") do
    assert_false File::Stat.new("#{dir}/test/executable").readable?
  end
end

assert 'File::Stat#readable_real?' do
  skip "when windows" if FileStatTest.win?

  dir = __FILE__[0..-18] # 18 = /test/file-stat.rb
  FileStatTest.chmod("+r-w-x", "#{dir}/test/readable") do
    assert_true File::Stat.new("#{dir}/test/readable").readable_real?
  end
  FileStatTest.chmod("-r+w-x", "#{dir}/test/writable") do
    assert_false File::Stat.new("#{dir}/test/writable").readable_real?
  end
  FileStatTest.chmod("-r-w+x", "#{dir}/test/executable") do
    assert_false File::Stat.new("#{dir}/test/executable").readable_real?
  end
end

assert 'File::Stat#world_readable?' do
  skip "when windows" if FileStatTest.win?

  dir = __FILE__[0..-18] # 18 = /test/file-stat.rb
  FileStatTest.system("chmod 0400 #{dir}/test/readable")
  assert_equal nil, File::Stat.new("#{dir}/test/readable").world_readable?
  FileStatTest.system("chmod 0444 #{dir}/test/readable")
  assert_equal 0444, File::Stat.new("#{dir}/test/readable").world_readable?
end

assert 'File::Stat#writable?' do
  dir = __FILE__[0..-18] # 18 = /test/file-stat.rb
  FileStatTest.chmod("+r-w-x", "#{dir}/test/readable") do
    assert_false File::Stat.new("#{dir}/test/readable").writable?
  end
  FileStatTest.chmod("-r+w-x", "#{dir}/test/writable") do
    assert_true File::Stat.new("#{dir}/test/writable").writable?
  end
  FileStatTest.chmod("-r-w+x", "#{dir}/test/executable") do
    assert_false File::Stat.new("#{dir}/test/executable").writable?
  end
end

assert 'File::Stat#writable_real?' do
  dir = __FILE__[0..-18] # 18 = /test/file-stat.rb
  FileStatTest.chmod("+r-w-x", "#{dir}/test/readable") do
    assert_false File::Stat.new("#{dir}/test/readable").writable_real?
  end
  FileStatTest.chmod("-r+w-x", "#{dir}/test/writable") do
    assert_true File::Stat.new("#{dir}/test/writable").writable_real?
  end
  FileStatTest.chmod("-r-w+x", "#{dir}/test/executable") do
    assert_false File::Stat.new("#{dir}/test/executable").writable_real?
  end
end

assert 'File::Stat#world_writable?' do
  skip "when windows" if FileStatTest.win?

  dir = __FILE__[0..-18] # 18 = /test/file-stat.rb
  FileStatTest.chmod("0600", "#{dir}/test/writable") do
    assert_equal nil, File::Stat.new("#{dir}/test/writable").world_writable?
  end
  FileStatTest.chmod("0666", "#{dir}/test/writable") do
    assert_equal 0666, File::Stat.new("#{dir}/test/writable").world_writable?
  end
end

assert 'File::Stat#executable?' do
  skip "when windows" if FileStatTest.win?

  dir = __FILE__[0..-18] # 18 = /test/file-stat.rb
  FileStatTest.chmod("+r-w-x", "#{dir}/test/readable") do
    assert_false File::Stat.new("#{dir}/test/readable").executable?
  end
  FileStatTest.chmod("-r+w-x", "#{dir}/test/writable") do
    assert_false File::Stat.new("#{dir}/test/writable").executable?
  end
  FileStatTest.chmod("-r-w+x", "#{dir}/test/executable") do
    assert_true File::Stat.new("#{dir}/test/executable").executable?
  end
end

assert 'File::Stat#executable_real?' do
  skip "when windows" if FileStatTest.win?

  dir = __FILE__[0..-18] # 18 = /test/file-stat.rb
  FileStatTest.chmod("+r-w-x", "#{dir}/test/readable") do
    assert_false File::Stat.new("#{dir}/test/readable").executable_real?
  end
  FileStatTest.chmod("-r+w-x", "#{dir}/test/writable") do
    assert_false File::Stat.new("#{dir}/test/writable").executable_real?
  end
  FileStatTest.chmod("-r-w+x", "#{dir}/test/executable") do
    assert_true File::Stat.new("#{dir}/test/executable").executable_real?
  end
end

assert 'File::Stat#file?' do
  stat = File::Stat.new('README.md')
  assert_true stat.file?

  stat = File::Stat.new('bin')
  assert_false stat.file?
end

assert 'File::Stat#zero?' do
  stat = File::Stat.new('README.md')
  assert_false stat.zero?
end

assert 'File::Stat#size?' do
  stat = File::Stat.new('README.md')
  assert_true 0 < stat.size?
end

assert 'File::Stat#owned?' do
  stat = File::Stat.new('README.md')
  assert_true stat.owned?
end

assert 'File::Stat#owned_real?' do
  stat = File::Stat.new('README.md')
  assert_true stat.owned_real?
end

assert 'File::Stat#grpowned?' do
  is_unix = File::Stat.new('/dev/tty') rescue false
  if is_unix
    stat = File::Stat.new('README.md')
    assert_true stat.grpowned?
  else
    skip "is not supported"
  end
end

assert 'File::Stat#pipe?' do
  stat = File::Stat.new('README.md')
  assert_false stat.pipe?
end

assert 'File::Stat#symlink?' do
  stat = File::Stat.new('README.md')
  assert_false stat.symlink?
end

assert 'File::Stat#socket?' do
  stat = File::Stat.new('README.md')
  assert_false stat.socket?
end

assert 'File::Stat#blockdev?' do
  stat = File::Stat.new('README.md')
  assert_false stat.blockdev?
end

assert 'File::Stat#chardev?' do
  stat = File::Stat.new('README.md')
  assert_false stat.chardev?

  begin
    stat = File::Stat.new('/dev/tty')
    assert_true stat.chardev?
  rescue RuntimeError
    skip '/dev/tty is not found'
  end
end

assert 'File::Stat#setuid?' do
  stat = File::Stat.new('README.md')
  assert_false stat.setuid?
end

assert 'File::Stat#setgid?' do
  stat = File::Stat.new('README.md')
  assert_false stat.setgid?
end

assert 'File::Stat#sticky?' do
  stat = File::Stat.new('README.md')
  assert_false stat.sticky?
end
