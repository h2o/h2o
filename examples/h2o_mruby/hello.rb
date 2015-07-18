# paths:
#   /:
#     file.dir: examples/doc_root
#     mruby.handler_path: /path/to/hello.rb

r = H2O::Request.new

h = "hello"
m =  "from h2o_mruby"

ua = r.headers_in["User-Agent"].to_s
host = r.headers_in["Accept"].to_s

r.headers_out["Hoge"] = "fuga"
hoge = r.headers_out["Hoge"]

msg = h + " " + m + " from " + ua + ":" + host + " " + hoge


r.log_error msg

msg + "\n"

