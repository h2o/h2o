MRuby::Gem::Specification.new 'mruby-compiler' do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'mruby compiler library'

  objs = %w[codegen y.tab].map do |name|
    src = "#{dir}/core/#{name}.c"
    if build.cxx_exception_enabled?
      build.compile_as_cxx(src)
    else
      objfile(src.pathmap("#{build_dir}/core/%n"))
    end
  end
  build.libmruby_core_objs << objs
end

if MRuby::Build.current.name == "host"
  dir = __dir__
  lex_def = "#{dir}/core/lex.def"

  # Parser
  file "#{dir}/core/y.tab.c" => ["#{dir}/core/parse.y", lex_def] do |t|
    MRuby.targets["host"].yacc.run t.name, t.prerequisites.first
    replace_line_directive(t.name)
  end

  # Lexical analyzer
  file lex_def => "#{dir}/core/keywords" do |t|
    MRuby.targets["host"].gperf.run t.name, t.prerequisites.first
    replace_line_directive(t.name)
  end

  def replace_line_directive(path)
    content = File.read(path).gsub(%r{
      ^\#line\s+\d+\s+"\K.*(?="$) |             # #line directive
      ^/\*\s+Command-line:.*\s\K\S+(?=\s+\*/$)  # header comment in lex.def
    }x, &:relative_path)
    File.write(path, content)
  end
end
