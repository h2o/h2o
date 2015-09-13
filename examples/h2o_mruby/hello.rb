# paths:
#   /:
#     file.dir: examples/doc_root
#     mruby.handler-file: /path/to/hello.rb

class HelloApp
  def call(env)
    h = "hello"
    m = "from h2o_mruby"

    ua = env["HTTP_USER_AGENT"]
    new_ua = "new-#{ua}-h2o_mruby"
    path = env["PATH_INFO"]
    host = env["HTTP_HOST"]
    method = env["REQUEST_METHOD"]
    query = env["QUERY_STRING"]

    msg = "#{h} #{m}. User-Agent:#{ua} New User-Agent:#{new_ua} path:#{path} host:#{host} method:#{method} query:#{query}"

    [200,
     {
       "content-type" => "text/plain; charset=utf-8",
       "user-agent" => new_ua,
     },
     ["#{msg}\n"]
    ]

  end
end

HelloApp.new
