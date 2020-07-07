desc 'generate document'
task :doc => [:api_doc, :capi_doc] do

end

desc 'generate yard docs'
task :api_doc do
  begin
    sh "mrbdoc"
  rescue
    puts "ERROR: To generate yard documentation, you should install yard-mruby gem."
    puts "  $ gem install yard-mruby yard-coderay"
  end
end

desc 'generate doxygen docs'
task :capi_doc do
  begin
    sh "doxygen Doxyfile"
  rescue
    puts "ERROR: To generate C API documents, you need Doxygen."
    puts "  $ sudo apt-get install doxygen"
  end
end

desc 'clean all built docs'
task :clean_api_doc do
  rm_rf 'doc/api'
end

desc 'clean all built docs'
task :clean_capi_doc do
  rm_rf 'doc/capi'
end

desc 'clean all built docs'
task :clean_doc => [:clean_api_doc, :clean_capi_doc] do
end

desc 'clean all built docs'
task :view_api => [:api_doc] do
  sh 'xdg-open doc/api/index.html'
end

desc 'clean all built docs'
task :view_capi => [:capi_doc] do
  sh 'xdg-open doc/capi/html/index.html'
end
