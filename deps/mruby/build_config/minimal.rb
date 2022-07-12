MRuby::CrossBuild.new('minimal') do |conf|
  conf.toolchain :gcc
  conf.cc.defines << 'MRB_NO_STDIO'
end
