MRuby::Gem::Specification.new 'mruby-compiler' do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'mruby compiler library'

  current_dir = spec.dir
  current_build_dir = spec.build_dir

  lex_def = "#{current_dir}/core/lex.def"
  core_objs = Dir.glob("#{current_dir}/core/*.c").map { |f|
    next nil if build.cxx_exception_enabled? and f =~ /(codegen).c$/
    objfile(f.pathmap("#{current_build_dir}/core/%n"))
  }.compact

  if build.cxx_exception_enabled?
    core_objs <<
      build.compile_as_cxx("#{current_build_dir}/core/y.tab.c", "#{current_build_dir}/core/y.tab.cxx",
                           objfile("#{current_build_dir}/y.tab"), ["#{current_dir}/core"]) <<
      build.compile_as_cxx("#{current_dir}/core/codegen.c", "#{current_build_dir}/core/codegen.cxx")
  else
    core_objs << objfile("#{current_build_dir}/core/y.tab")
    file objfile("#{current_build_dir}/core/y.tab") => "#{current_build_dir}/core/y.tab.c" do |t|
      cc.run t.name, t.prerequisites.first, [], ["#{current_dir}/core"]
    end
  end
  file objfile("#{current_build_dir}/core/y.tab") => lex_def

  # Parser
  file "#{current_build_dir}/core/y.tab.c" => ["#{current_dir}/core/parse.y"] do |t|
    yacc.run t.name, t.prerequisites.first
  end

  # Lexical analyzer
  file lex_def => "#{current_dir}/core/keywords" do |t|
    gperf.run t.name, t.prerequisites.first
  end

  file libfile("#{build.build_dir}/lib/libmruby_core") => core_objs
  build.libmruby << core_objs
end
