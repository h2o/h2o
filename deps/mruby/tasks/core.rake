as_cxx_srcs = %w[vm error gc].map{|name| "#{MRUBY_ROOT}/src/#{name}.c"}

MRuby.each_target do
  objs = Dir.glob("#{MRUBY_ROOT}/src/*.c").map do |src|
    if cxx_exception_enabled? && as_cxx_srcs.include?(src)
      compile_as_cxx(src)
    else
      objfile(src.pathmap("#{build_dir}/src/%n"))
    end
  end
  self.libmruby_core_objs << objs
end
