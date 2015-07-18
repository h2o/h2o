# paths:
#   /:
#     file.dir: examples/doc_root
#     mruby.handler_path: /path/to/hello.rb

r = H2O::Request.new

h = "hello"
m =  "from h2o_mruby"

ua = r.headers_in["User-Agent"].to_s
host = r.headers_in["Accept"].to_s

msg = h + " " + m + " from " + ua + ":" + host

r.log_error msg

msg + "\n"

