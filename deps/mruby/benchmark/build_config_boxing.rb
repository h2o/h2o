MRuby::Build.new do |conf|
  toolchain :gcc
end

MRuby::Build.new('no_boxing') do |conf|
  toolchain :gcc

  conf.gembox 'default'
end

MRuby::Build.new('word_boxing') do |conf|
  toolchain :gcc

  conf.gembox 'default'
  conf.compilers.each do |c|
    c.defines += %w(MRB_WORD_BOXING)
  end
end

MRuby::Build.new('nan_boxing') do |conf|
  toolchain :gcc

  conf.gembox 'default'
  conf.compilers.each do |c|
    c.defines += %w(MRB_NAN_BOXING)
  end
end

