# mruby-io

`IO` and `File` classes for mruby

## Installation

Add the line below to your build configuration.

```
  conf.gem core: 'mruby-io'
```

## Implemented methods

### IO

* <https://doc.ruby-lang.org/ja/1.9.3/class/IO.html>

| method                     | mruby-io | memo |
| -------------------------  | -------- | ---- |
| IO.binread                 |          |      |
| IO.binwrite                |          |      |
| IO.copy_stream             |          |      |
| IO.new, IO.for_fd, IO.open |  o  |     |
| IO.foreach                 |          |      |
| IO.pipe                    |    o     |      |
| IO.popen                   |    o     |      |
| IO.read                    |    o     |      |
| IO.readlines               |          |      |
| IO.select                  |    o     |      |
| IO.sysopen                 |    o     |      |
| IO.try_convert             |          |      |
| IO.write                   |          |      |
| IO#<<                      |          |      |
| IO#advise                  |          |      |
| IO#autoclose=              |          |      |
| IO#autoclose?              |          |      |
| IO#binmode                 |          |      |
| IO#binmode?                |          |      |
| IO#bytes                   |          | obsolete |
| IO#chars                   |          | obsolete |
| IO#clone, IO#dup           |    o     |      |
| IO#close                   |    o     |      |
| IO#close_on_exec=          |    o     |      |
| IO#close_on_exec?          |    o     |      |
| IO#close_read              |          |      |
| IO#close_write             |          |      |
| IO#closed?                 |    o     |      |
| IO#codepoints              |          | obsolete |
| IO#each_byte               |    o     |      |
| IO#each_char               |    o     |      |
| IO#each_codepoint          |          |      |
| IO#each_line               |    o     |      |
| IO#eof, IO#eof?            |    o     |      |
| IO#external_encoding       |          |      |
| IO#fcntl                   |          |      |
| IO#fdatasync               |          |      |
| IO#fileno, IO#to_i         |    o     |      |
| IO#flush                   |    o     |      |
| IO#fsync                   |          |      |
| IO#getbyte                 |    o     |      |
| IO#getc                    |    o     |      |
| IO#gets                    |    o     |      |
| IO#internal_encoding       |          |      |
| IO#ioctl                   |          |      |
| IO#isatty, IO#tty?         |    o     |      |
| IO#lineno                  |          |      |
| IO#lineno=                 |          |      |
| IO#lines                   |          | obsolete |
| IO#pid                     |    o     |      |
| IO#pos, IO#tell            |    o     |      |
| IO#pos=                    |    o     |      |
| IO#print                   |    o     |      |
| IO#printf                  |    o     |      |
| IO#putc                    |          |      |
| IO#puts                    |    o     |      |
| IO#read                    |    o     |      |
| IO#read_nonblock           |          |      |
| IO#readbyte                |    o     |      |
| IO#readchar                |    o     |      |
| IO#readline                |    o     |      |
| IO#readlines               |    o     |      |
| IO#readpartial             |          |      |
| IO#reopen                  |          |      |
| IO#rewind                  |          |      |
| IO#seek                    |    o     |      |
| IO#set_encoding            |          |      |
| IO#stat                    |          |      |
| IO#sync                    |    o     |      |
| IO#sync=                   |    o     |      |
| IO#sysread                 |    o     |      |
| IO#sysseek                 |    o     |      |
| IO#syswrite                |    o     |      |
| IO#to_io                   |          |      |
| IO#ungetbyte               |    o     |      |
| IO#ungetc                  |    o     |      |
| IO#write                   |    o     |      |
| IO#write_nonblock          |          |      |

### File

* <https://doc.ruby-lang.org/ja/1.9.3/class/File.html>

| method                      | mruby-io | memo |
| --------------------------- | -------- | ---- |
| File.absolute_path          |          |      |
| File.atime                  |          |      |
| File.basename               |   o      |      |
| File.blockdev?              |          | FileTest |
| File.chardev?               |          | FileTest |
| File.chmod                  |   o      |      |
| File.chown                  |          |      |
| File.ctime                  |          |      |
| File.delete, File.unlink    |   o      |      |
| File.directory?             |   o      | FileTest |
| File.dirname                |   o      |      |
| File.executable?            |          | FileTest |
| File.executable_real?       |          | FileTest |
| File.exist?, exists?        |   o      | FileTest |
| File.expand_path            |   o      |      |
| File.extname                |   o      |      |
| File.file?                  |   o      | FileTest |
| File.fnmatch, File.fnmatch? |          |      |
| File.ftype                  |          |      |
| File.grpowned?              |          | FileTest |
| File.identical?             |          | FileTest |
| File.join                   |   o      |      |
| File.lchmod                 |          |      |
| File.lchown                 |          |      |
| File.link                   |          |      |
| File.lstat                  |          |      |
| File.mtime                  |          |      |
| File.new, File.open         |   o      |      |
| File.owned?                 |          | FileTest |
| File.path                   |          |      |
| File.pipe?                  |   o      | FileTest |
| File.readable?              |          | FileTest |
| File.readable_real?         |          | FileTest |
| File.readlink               |   o      |      |
| File.realdirpath            |          |      |
| File.realpath               |   o      |      |
| File.rename                 |   o      |      |
| File.setgid?                |          | FileTest |
| File.setuid?                |          | FileTest |
| File.size                   |   o      |      |
| File.size?                  |   o      | FileTest |
| File.socket?                |   o      | FileTest |
| File.split                  |          |      |
| File.stat                   |          |      |
| File.sticky?                |          | FileTest |
| File.symlink                |          |      |
| File.symlink?               |   o      | FileTest |
| File.truncate               |          |      |
| File.umask                  |   o      |      |
| File.utime                  |          |      |
| File.world_readable?        |          |      |
| File.world_writable?        |          |      |
| File.writable?              |          | FileTest |
| File.writable_real?         |          | FileTest |
| File.zero?                  |   o      | FileTest |
| File#atime                  |          |      |
| File#chmod                  |          |      |
| File#chown                  |          |      |
| File#ctime                  |          |      |
| File#flock                  |   o      |      |
| File#lstat                  |          |      |
| File#mtime                  |          |      |
| File#path, File#to_path     |   o      |      |
| File#size                   |          |      |
| File#truncate               |          |      |

## License

Copyright (c) 2013 Internet Initiative Japan Inc.
Copyright (c) 2017 mruby developers

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
