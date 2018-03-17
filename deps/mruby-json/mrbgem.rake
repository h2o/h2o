MRuby::Gem::Specification.new('mruby-json') do |spec|
  spec.license = 'MIT'
  spec.authors = 'mattn'
  spec.cc.defines << 'JSON_FIXED_NUMBER'
end
