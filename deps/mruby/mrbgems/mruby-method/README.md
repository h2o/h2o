# mruby-method

An implementation of class **Method** and **UnboundMethod** for mruby

```ruby
p Enumerable.instance_method(:find_all).source_location
#=> ["mruby/mruby/mrblib/enum.rb", 148]
```

# Note

You need to enable debug option in your build configuration to use
`source_location` method in this gem, for example:

```ruby
MRuby::Build.new do |conf|
  conf.enable_debug
end
```

# Supported Methods

## Kernel

* `Kernel#method`
* `Kernel#singleton_method`

## Module

* `Module#instance_method`

## Method class

* `Method#name`
* `Method#call`
* `Method#super_method`
* `Method#arity`
* `Method#unbind`
* `Method#[]`
* `Method#owner`
* `Method#receiver`
* `Method#parameters`
* `Method#source_location`
* `Method#to_proc`

## UnboundMethod class

* `UnboundMethod#name`
* `UnboundMethod#bind`
* `UnboundMethod#super_method`
* `UnboundMethod#arity`
* `UnboundMethod#owner`
* `UnboundMethod#parameters`
* `UnboundMethod#source_location`

# See also

* <https://ruby-doc.org/core-2.3.3/Method.html>
* <https://ruby-doc.org/core-2.3.3/UnboundMethod.html>
