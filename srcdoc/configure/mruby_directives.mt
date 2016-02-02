? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Mruby Directives")->(sub {

<p>
<a href="https://github.com/mruby/mruby">mruby</a> is a lightweight implemenation of the Ruby programming language.
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
        if /\A192\.168\./.match(req["REMOTE_ADDR"])
          return [399, {}, []]
        end
        [403, {'content-type' => 'text/plain'}, ["access forbidden\n"]]
      end
EOT
?>

<h3 id="delegating-request">Delegating the Request</h3>

<p>
When enabled using the <a href="configure/reproxy_directives.html#reproxy"><code>reproxy</code></a> directive, it is possible to delegate the request from the mruby handler to any other handler.
</p>
<p>
<?= $ctx->{example}->('Pushing asset files', <<'EOT')
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
          push_paths << "/css/style.css"
          push_paths << "/js/app.js"
        end
        [399, push_paths.empty? ? {} : {"link" => push_paths.map{|p| "<#{p}>; rel=preload"}.join("\n")}, []]
      end
    fastcgi.connect: ...
EOT
?>

<p>
The following are the configuration directives of the mruby handler.
</p>

<?
$ctx->{directive}->(
    name     => "mruby.handler",
    levels   => [ qw(path) ],
    see_also => render_mt(<<'EOT'),
<a href="configure/mruby_directives.html#mruby.handler-file"><code>mruby.handler-file</code></a>
EOT
    desc     => <<'EOT',
Upon start-up evaluates given mruby expression, and uses the returned mruby object to handle the incoming requests.
EOT
)->(sub {
?>

<?= $ctx->{example}->('Hello-world in mruby', <<'EOT')
mruby.handler: |
  Proc.new do |env|
    [200, {'content-type' => 'text/plain'}, ["Hello world\n"]]
  end
EOT
?>

<p>
Note that the provided expression is evaluated more than once (typically for every thread that accepts incoming connections).
</p>
? })

<?
$ctx->{directive}->(
    name     => "mruby.handler-file",
    levels   => [ qw(path) ],
    see_also => render_mt(<<'EOT'),
<a href="configure/mruby_directives.html#mruby.handler"><code>mruby.handler</code></a>
EOT
    desc     => <<'EOT',
Upon start-up evaluates given mruby file, and uses the returned mruby object to handle the incoming requests.
EOT
)->(sub {
?>

<?= $ctx->{example}->('Hello-world in mruby', <<'EOT')
mruby.handler-file: /path/to/my-mruby-handler.rb
EOT
?>

<p>
Note that the provided expression is evaluated more than once (typically for every thread that accepts incoming connections).
</p>
? })

? })
