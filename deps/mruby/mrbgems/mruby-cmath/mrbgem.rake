# This `mruby-cmath` gem uses C99 _Complex features
# You need C compiler that support C99+
MRuby::Gem::Specification.new('mruby-cmath') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'standard Math module with complex'
  spec.add_dependency 'mruby-complex'
end
