# paths:
#   /:
#     file.dir: examples/doc_root
#     mruby.handler_path: /path/to/hello.rb

h = "hello"
m =  "from h2o_mruby"
H2O::Request.new.log_error h + m
h + " " + m + "\n"
