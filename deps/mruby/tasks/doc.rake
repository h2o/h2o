desc 'generate document'
task :doc => %w[doc:api doc:capi]

namespace :doc do
  desc 'generate yard docs'
  task :api do
    begin
      sh "mrbdoc"
    rescue
      puts "ERROR: To generate yard documentation, you should install yard-mruby gem."
      puts "  $ gem install yard-mruby yard-coderay"
    end
  end

  desc 'generate doxygen docs'
  task :capi do
    begin
      sh "doxygen Doxyfile"
    rescue
      puts "ERROR: To generate C API documents, you need Doxygen."
      puts "On Debian-based systems:"
      puts "  $ sudo apt-get install doxygen"
      puts "On RHEL-based systems:"
      puts "  $ sudo dnf install doxygen"
    end
  end

  desc 'clean all built docs'
  task :clean => %w[clean:api clean:capi]

  namespace :clean do
    desc 'clean yard docs'
    task :api do
      rm_rf 'doc/api'
    end

    desc 'clean doxygen docs'
    task :capi do
      rm_rf 'doc/capi'
    end
  end

  namespace :view do
    desc 'open yard docs'
    task :api do
      sh 'xdg-open doc/api/index.html'
    end

    desc 'open doxygen docs'
    task :capi do
      sh 'xdg-open doc/capi/html/index.html'
    end
  end
end

# deprecated
task "api_doc" => "doc:api"
task "capi_doc" => "doc:capi"
task "clean_doc" => "doc:clean"
task "clean_api_doc" => "doc:clean:api"
task "clean_capi_doc" => "doc:clean:capi"
task "view_api" => "doc:view:api"
task "view_capi" => "doc:view:capi"
