? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Using Mruby")->(sub {

<p>
<a href="https://github.com/mruby/mruby">mruby</a> is a lightweight implementation of the Ruby programming language.
With H2O, users can implement their own request handling logic using mruby, either to generate responses or to fix-up the request / response.
</p>

<h3 id="programming-interface">Rack-based Programming Interface</h3>

<p>
The interface between the mruby program and the H2O server is based on <a href="http://www.rubydoc.info/github/rack/rack/master/file/SPEC">Rack interface specification</a>.
Below is a simple configuration that returns <i>hello world</i>.
</p>

<?= $ctx->{example}->('Hello-world in mruby', <<'EOT')
paths:
  "/":
    mruby.handler: |
      Proc.new do |env|
        [200, {'content-type' => 'text/plain'}, ["Hello world\n"]]
      end
EOT
?>

<p>
It should be noted that as of H2O version 1.7.0, there are limitations when compared to ordinary web application server with support for Rack such as Unicorn:
<ul>
<li>no libraries provided as part of Rack is available (only the interface is compatible)
</ul>
</p>

<p>
In addition to the Rack interface specification, H2O recognizes status code <code>399</code> which can be used to delegate request to the next handler.
The feature can be used to implement access control and response header modifiers.
</p>

<h3 id="access-control">Access Control</h3>

<p>
By using the <code>399</code> status code, it is possible to implement access control using mruby.
The example below restricts access to requests from <code>192.168.</code> private address.
</p>

<?= $ctx->{example}->('Restricting access to 192.168.', <<'EOT')
paths:
  "/":
    mruby.handler: |
      lambda do |env|
        if /\A192\.168\./.match(env["REMOTE_ADDR"])
          return [399, {}, []]
        end
        [403, {'content-type' => 'text/plain'}, ["access forbidden\n"]]
      end
EOT
?>

<p>
Support for <a href="configure/basic_auth.html">Basic Authentication</a> is also provided by an mruby script.
</p>

<h3 id="delegating-request">Delegating the Request</h3>

<p>
When enabled using the <a href="configure/reproxy_directives.html#reproxy"><code>reproxy</code></a> directive, it is possible to delegate the request from the mruby handler to any other handler.
</p>
<p>
<?= $ctx->{example}->('Rewriting URL with delegation', <<'EOT')
paths:
  "/":
    mruby.handler: |
      lambda do |env|
        if /\/user\/([^\/]+)/.match(env["PATH_INFO"])
          return [307, {"x-reproxy-url" => "/user.php?user=#{$1}"}, []]
        end
        return [399, {}, []]
      end
EOT
?>

<h3 id="modifying-response">Modifying the Response</h3>

<p>
When the mruby handler returns status code <code>399</code>, H2O delegates the request to the next handler while preserving the headers emitted by the handler.
The feature can be used to add extra headers to the response.
</p>
<p>
For example, the following example sets <code>cache-control</code> header for requests against <code>.css</code> and <code>.js</code> files.
</p>

<?= $ctx->{example}->('Setting cache-control header for certain types of files', <<'EOT')
paths:
  "/":
    mruby.handler: |
      Proc.new do |env|
        headers = {}
        if /\.(css|js)\z/.match(env["PATH_INFO"])
          headers["cache-control"] = "max-age=86400"
        end
        [399, headers, []]
      end
    file.dir: /path/to/doc-root
EOT
?>

<p>
Or in the example below, the handler triggers <a href="configure/http2_directives.html#server-push">HTTP/2 server push</a> with the use of <code>Link: rel=preload</code> headers, and then requests a FastCGI application to process the request.
</p>

<?= $ctx->{example}->('Pushing asset files', <<'EOT')
paths:
  "/":
    mruby.handler: |
      Proc.new do |env|
        push_paths = []
        # push css and js when request is to dir root or HTML
        if /(\/|\.html)\z/.match(env["PATH_INFO"])
          push_paths << ["/css/style.css", "style"]
          push_paths << ["/js/app.js", "script"]
        end
        [399, push_paths.empty? ? {} : {"link" => push_paths.map{|p| "<#{p[0]}>; rel=preload; as=#{p[1]}"}.join("\n")}, []]
      end
    fastcgi.connect: ...
EOT
?>

<h3 id="http-client">Using the HTTP Client</h3>

<p>
Starting from version 1.7, a HTTP client API is provided.
HTTP requests issued through the API will be handled asynchronously; the client does not block the event loop of the HTTP server.
</p>

<?= $ctx->{example}->('Mruby handler returning the response of http://example.com', <<'EOT')
paths:
  "/":
    mruby.handler: |
      Proc.new do |env|
        req = http_request("http://example.com")
        status, headers, body = req.join
        [status, headers, body]
      end
EOT
?>

<p>
<code>http_request</code> is the method that issues a HTTP request.
</p>
<p>
The method takes two arguments.
First argument is the target URI.
Second argument is an optional hash; <code>method</code> (defaults to <code>GET</code>), <code>header</code>, <code>body</code> attributes are recognized.
</p>
<p>
The method returns a promise object.
When <code>#join</code> method of the promise is invoked, a three-argument array containing the status code, response headers, and the body is returned.
The response body is also a promise.
Applications can choose from three ways when dealing with the body: a) call <code>#each</code> method to receive the contents, b) call <code>#join</code> to retrieve the body as a string, c) return the object as the response body of the mruby handler.
</p>
<p>
The header and the body object passed to <code>http_request</code> should conform to the requirements laid out by the Rack specification for request header and request body.
The response header and the response body object returned by the <code>#join</code> method of the promise returned by <code>http_request</code> conforms to the requirements of the Rack specification.
</p>
<p>
Since the API provides an asynchronous HTTP client, it is possible to effectively issue multiple HTTP requests concurrently and merge them into a single response.
</p>
<p>
When HTTPS is used, servers are verified using the properties of <a href="configure/proxy_directives.html#proxy.ssl.cafile"><code>proxy.ssl.cafile</code></a> and <a href="configure/proxy_directives.html#proxy.ssl.verify-peer"><code>proxy.ssl.verify-peer</code></a> specified at the global level.
</p>

<h3 id="logging-arbitrary-variable">Logging Arbitrary Variable</h3>

<p>
In version 2.3, it is possible from mruby to set and log an arbitrary-named variable that is associated to a HTTP request.
A HTTP response header that starts with <code>x-fallthru-set-</code> is handled specially by the H2O server. Instead of sending the header downstream, the server accepts the value as a request environment variable, taking the suffix of the header name as the name of the variable.
</p>
<p>
This example shows how to read request data, parse json and then log data from mruby.
</p>

<?= $ctx->{example}->('Logging the content of a POST request via request environment variable', <<'EOT')
paths:
  "/":
    mruby.handler: |
      Proc.new do |env|
        input = env["rack.input"] ? env["rack.input"].read : '{"default": "true"}'
        parsed_json = JSON.parse(input)
        parsed_json["time"] = Time.now.to_i
        logdata = parsed_json.to_s
        [204, {"x-fallthru-set-POSTDATA" => logdata}, []]
      end
    access-log:
      path: /path/to/access-log.json
      escape: json
      format: '{"POST": %{POSTDATA}e}'
EOT
?>

? })
