MRUBY_CONFIG=File.expand_path(ENV["MRUBY_CONFIG"] || "./build_config.rb")

file :mruby do
  sh "git clone --depth 1 git://github.com/mruby/mruby.git"
end

desc "test"
task :test => :mruby do
  sh "cd mruby && MRUBY_CONFIG=#{MRUBY_CONFIG} rake test"
end

desc "cleanup"
task :clean do
  sh "cd mruby && rake deep_clean"
end
