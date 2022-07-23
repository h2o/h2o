mruby_version = ENV["MRUBY_VERSION"] || 'master'
mruby_dir = "mruby-#{mruby_version}"

file 'mruby-head' do
  sh "git clone --depth 1 --no-single-branch git://github.com/mruby/mruby.git"
  sh "mv mruby mruby-head"
end

file mruby_dir => 'mruby-head' do
  sh "cp -a mruby-head #{mruby_dir}"
  cd mruby_dir do
    sh "git checkout #{mruby_version}"
  end
end

file "#{mruby_dir}/ci_build_config.rb" => [mruby_dir, ".ci_build_config.rb"] do
  sh "cp #{File.expand_path(".ci_build_config.rb")} #{mruby_dir}/ci_build_config.rb"
end

desc "run test with mruby"
task :test => "#{mruby_dir}/ci_build_config.rb" do
  cd mruby_dir do
    sh "rake -E 'STDOUT.sync=true' test all MRUBY_CONFIG=ci_build_config.rb"
  end
end
