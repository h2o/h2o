# mruby-json

[![Build Status](https://travis-ci.org/mattn/mruby-json.svg)](https://travis-ci.org/mattn/mruby-json)

JSON parser for mruby

## install by mrbgems
```ruby
MRuby::Build.new do |conf|

    # ... (snip) ...

    conf.gem :github => 'mattn/mruby-json'
end
```

## License

MIT

## Note

This repository include fork of [parson](https://github.com/kgabis/parson) library because parson only handle 11 bits precision for fixed numbers. I think original policy is right on the implementing JSON. But not useful to handle 64bit numbers on mruby. If you want to contribute to the source parson.c or parson.h, please send PR to my [fork](https://github.com/mattn/parson).

## Author

Yasuhiro Matsumoto (a.k.a mattn)
