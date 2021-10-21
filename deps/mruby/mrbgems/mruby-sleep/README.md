# Sleep Module for mruby
mruby sleep module

## install by mrbgems
 - add conf.gem line to `build_config.rb`
```ruby
MRuby::Build.new do |conf|

    # ... (snip) ...

    conf.gem :core => 'mruby-sleep'
end
```

## example

```ruby
sleep(10)
usleep(10000)
```

# License
under the MIT License:

* http://www.opensource.org/licenses/mit-license.php


