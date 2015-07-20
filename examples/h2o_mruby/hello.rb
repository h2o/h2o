# paths:
#   /:
#     file.dir: examples/doc_root
#     mruby.handler_path: /path/to/hello.rb

r = H2O::Request.new

h = "hello"
m =  "from h2o_mruby"

ua = r.headers_in["User-Agent"].to_s
new_ua = r.headers_in["User-Agent"] = "new-#{ua}-h2o_mruby"
uri = r.uri
host = r.hostname
method = r.method

msg = "#{h} #{m}. User-Agent:#{ua} New User-Agent:#{new_ua} path:#{uri} host:#{host} method:#{method}"

r.log_error msg

H2O.return 200, "OK", msg + "\n"
