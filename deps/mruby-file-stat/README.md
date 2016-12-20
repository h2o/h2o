# mruby-file-stat

[![Build Status](https://travis-ci.org/ksss/mruby-file-stat.svg?branch=master)](https://travis-ci.org/ksss/mruby-file-stat)
[![Build status](https://ci.appveyor.com/api/projects/status/04am84uda2cj49n3/branch/master?svg=true)](https://ci.appveyor.com/project/ksss/mruby-file-stat/branch/master)

**File::Stat** class in mruby

```ruby
stat = File::Stat.new('filename') # or File.stat('filename')
stat.dev #=> device id
stat.dev_major #=> device major id
stat.dev_minor #=> device minor id
stat.ino #=> i-node number
stat.mode #=> permission value (st_mode)
stat.nlink #=> hard link count
stat.uid #=> user id
stat.gid #=> group id
stat.rdev #=> device type
stat.rdev_major #=> rdev major id
stat.rdev_minor #=> rdev minor id
stat.atime #=> last access time
stat.mtime #=> last modify time
stat.ctime #=> last change attribute time
stat.birthtime #=> file created time
stat.size #=> file size(byte)
stat.blksize #=> file I/O block size
stat.blocks #=> attached block num
stat.grpowned #=> same gid?
stat.<=> #=> comparate mtime (-1,0,1 or nil)
stat.size?
stat.zero?
stat.symlink?
stat.file?
stat.directory?
stat.chardev?
stat.blockdev?
stat.pipe?
stat.socket?
stat.owned?
stat.owned_real?
stat.readable?
stat.readable_real?
stat.writable?
stat.writable_real?
stat.executable?
stat.executable_real?
stat.world_readable?
stat.world_writable?
stat.setuid?
stat.setgid?
stat.sticky?
stat.ftype #=> socket, link, file, blockSpecial, directory, characterSpecial, fifo or unknown
```

This library is wrap of struct stat.

## Installation

### use github repository

Write in /mruby/build_config.rb

```ruby
MRuby::Build.new do |conf|
  # by mgem
  conf.gem :mgem => 'mruby-file-stat'
  # by github
  conf.gem :github => 'ksss/mruby-file-stat', :branch => 'master'
end
```

## Homepage

https://github.com/ksss/mruby-file-stat

## License

See [https://github.com/ruby/ruby/blob/trunk/file.c](https://github.com/ruby/ruby/blob/trunk/file.c)

## Doc

[http://ruby-doc.org/core-2.1.5/File/Stat.html](http://ruby-doc.org/core-2.1.5/File/Stat.html)
