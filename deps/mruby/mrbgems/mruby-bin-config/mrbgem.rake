unless MRuby::Build.current.kind_of?(MRuby::CrossBuild)
  MRuby::Gem::Specification.new('mruby-bin-config') do |spec|
    name = 'mruby-config'
    spec.license = 'MIT'
    spec.author  = 'mruby developers'
    spec.summary = "#{name} command"

    mruby_config = name + (ENV['OS'] == 'Windows_NT' ? '.bat' : '')
    mruby_config_path = "#{build.build_dir}/bin/#{mruby_config}"
    make_cfg = "#{build.build_dir}/lib/libmruby.flags.mak"
    build.bins << mruby_config

    file mruby_config_path => [build.libmruby_static, make_cfg] do |t|
      config = Hash[File.readlines(make_cfg).map(&:chomp).map {|l|
        l.gsub('\\"', '"').split(' = ', 2).map! {|s| s.sub(/^(?=.)/, 'echo ')}
      }]
      tmplt = File.read("#{__dir__}/#{mruby_config}")
      File.write(t.name, tmplt.gsub(/(#{Regexp.union(*config.keys)})\b/, config))
      FileUtils.chmod(0755, t.name)
    end
  end
end
