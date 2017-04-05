MRuby.each_target do
  current_dir = File.dirname(__FILE__).relative_path_from(Dir.pwd)
  relative_from_root = File.dirname(__FILE__).relative_path_from(MRUBY_ROOT)
  current_build_dir = "#{build_dir}/#{relative_from_root}"

  objs = Dir.glob("#{current_dir}/*.c").map { |f|
    next nil if cxx_exception_enabled? and f =~ /(error|vm).c$/
    objfile(f.pathmap("#{current_build_dir}/%n"))
  }.compact

  if cxx_exception_enabled?
    objs += %w(vm error).map { |v| compile_as_cxx "#{current_dir}/#{v}.c", "#{current_build_dir}/#{v}.cxx" }
  end
  self.libmruby << objs

  file libfile("#{build_dir}/lib/libmruby_core") => objs do |t|
    archiver.run t.name, t.prerequisites
  end
end
