H2O - an optimized HTTP server with support for HTTP/1.x and HTTP/2
===

[![Build Status](https://travis-ci.org/h2o/h2o.svg?branch=master)](https://travis-ci.org/h2o/h2o)
<a href="https://scan.coverity.com/projects/h2o-h2o">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/10654/badge.svg"/>
</a>

(For more information, please refer to the documentation at [h2o.examp1e.net](https://h2o.examp1e.net))

H2O is a new generation HTTP server.
Not only is it very fast, it also provides much quicker response to end-users when compared to older generations of HTTP servers.

Written in C and licensed under [the MIT License](http://opensource.org/licenses/MIT) (see LICENSE for more details &
copyright attribution). It can also be used as a library.

This fork is modified to enable PostgreSQL mruby module.

If necessary, as demonstrated below, specify the `-DPG_LIBRARY=...` and `-DPG_INCLUDE=...` flags for cmake


### OSX Compilation & Installation Example

```bash
  brew install libpq
  # --> installs sometimes to /usr/local/opt/libpq if you already have postgres installed (for example)

  cmake -DENABLE_MRUBY=true -DPG_LIBRARY=/usr/local/opt/libpq/lib/libpq.a -DPG_INCLUDE=/usr/local/opt/libpq/include/ .
  make
  sudo make install
```
