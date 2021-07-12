MRuby::Gem::Specification.new 'mruby-compiler' do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'mruby compiler library'

  lex_def = "#{dir}/core/lex.def"
  core_objs = Dir.glob("#{dir}/core/*.c").map { |f|
    next nil if build.cxx_exception_enabled? and f =~ /(codegen).c$/
    objfile(f.pathmap("#{build_dir}/core/%n"))
  }.compact

  if build.cxx_exception_enabled?
    core_objs <<
      build.compile_as_cxx("#{dir}/core/y.tab.c", "#{build_dir}/core/y.tab.cxx",
                           objfile("#{build_dir}/y.tab"), ["#{dir}/core"]) <<
      build.compile_as_cxx("#{dir}/core/codegen.c", "#{build_dir}/core/codegen.cxx")
  else
    core_objs << objfile("#{build_dir}/core/y.tab")
    file objfile("#{build_dir}/core/y.tab") => "#{dir}/core/y.tab.c" do |t|
      cc.run t.name, t.prerequisites.first, [], ["#{dir}/core"]
    end
  end

  # Parser
  file "#{dir}/core/y.tab.c" => ["#{dir}/core/parse.y", lex_def] do |t|
    yacc.run t.name, t.prerequisites.first
    content = File.read(t.name).gsub(/^#line +\d+ +"\K.*$/){$&.relative_path}
    File.write(t.name, content)
  end

  # Lexical analyzer
  file lex_def => "#{dir}/core/keywords" do |t|
    gperf.run t.name, t.prerequisites.first
  end

  file build.libmruby_core_static => core_objs
  build.libmruby << core_objs
end
