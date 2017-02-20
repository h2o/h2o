module MRuby
  class Build
    def exefile(name)
      if name.is_a?(Array)
        name.flatten.map { |n| exefile(n) }
      elsif name !~ /\./
        "#{name}#{exts.executable}"
      else
        name
      end
    end
  end
end

MRuby.each_target do
  next if kind_of? MRuby::CrossBuild

  mruby_config = 'mruby-config' + (ENV['OS'] == 'Windows_NT' ? '.bat' : '')
  mruby_config_path = "#{build_dir}/bin/#{mruby_config}"
  @bins << mruby_config

  file mruby_config_path => libfile("#{build_dir}/lib/libmruby") do |t|
    FileUtils.copy "#{File.dirname(__FILE__)}/#{mruby_config}", t.name
    config = Hash[open("#{build_dir}/lib/libmruby.flags.mak").read.split("\n").map {|x| a = x.split(/\s*=\s*/, 2); [a[0], a[1].gsub('\\"', '"') ]}]
    IO.write(t.name, File.open(t.name) {|f|
      f.read.gsub (/echo (MRUBY_CFLAGS|MRUBY_LIBS|MRUBY_LDFLAGS_BEFORE_LIBS|MRUBY_LDFLAGS)/) {|x| config[$1].empty? ? '' : "echo #{config[$1]}"}
    })
    FileUtils.chmod(0755, t.name)
  end
end
