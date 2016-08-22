? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Access Control")->(sub {

<p>
Starting from version 2.1, H2O comes with a DSL-like mruby library which make it easy to write access control list (ACL).
</p>

<h2 id="example" class="section-head">Example</h2>

<p>
Below example uses this Access Control feature to write various access control.
</p>

<?= $ctx->{example}->('Access Control', <<'EOT');
paths:
  "/":
    mruby.handler: |
      acl {
        allow { addr == "127.0.0.1" }
        deny { user_agent.match(/curl/i) && ! addr.start_with?("192.168.") }
        respond(503, {}, ["Service Unavailable"]) { addr == malicious_ip }
        redirect("https://somewhere.com/", 301) { path =~ /moved/ }
        use Htpasswd.new("/path/to/.htpasswd", "realm") { path.start_with?("/admin") }
      }
    file.dir: /path/to/doc_root
EOT
?>

<p>
In the example above, the handler you got by calling <code>acl</code> method will do the following:
<ul>
  <li>
    If the remote IP address exactly equals to "127.0.0.1", the request will be delegated to the next handler (i.e. serve files under /path/to/doc_root) and all following acl settings is ignored.
  </li>
  <li>
    Otherwise, if the user agent string includes "curl" and the remote IP address doesn't start with "192.168.", this handler immediately returns <code>403 Forbidden</code> response.
  </li>
  <li>
    Otherwise, if the remote IP address is exactly equals to the <code>malicious_ip</code> variable, this handler immediately returns <code>503 Service Unavailable</code> response.
  </li>
  <li>
    Otherwise, if the request path matches with the pattern <code>/moved/i</code>, this handler immediately redirects the client to <code>"https://somewhere.com"</code> with <code>301</code> status code.
  </li>
  <li>
    Otherwise, if the request path starts with <code>/admin</code>, apply Basic Authentication to the request. (for details of Basic Authentication, see <a href="configure/basic_auth.html">here</a>).
  </li>
  <li>
    Otherwise, the request will be delegated to the next handler (i.e. serve files under /path/to/doc_root)
  </li>

</ul>

<h2 id="acl-methods" class="section-head">ACL Methods</h2>

<p>
An ACL handler is built by calling ACL methods, which can be used like directives.
ACL methods can only be used in <code>acl</code> block.
</p>

<p>
Each ACL method adds a filter to the handler, which checks whether the request matches the provided condition or not.
All ACL methods accept the condition block, which should return boolean value. If condition block is missing, all requests matches.
</p>

<p>
If the request matches the condition, the handler do the specific process defined per each method (for example: response <code>403 Forbidden</code>, redirect to somewhere, etc).
If the request doesn't match any filter's conditions, the handler returns <code>399</code> and the request will be delegated to the next handler.
</p>

<?
$ctx->{mruby_method}->(
    name    => "allow",
    desc    => q{Add a filter which delegate the request to the next handler if the request matches the provided condition},
)->(sub {
?>
<pre><code>allow { ..condition.. }</code></pre>
? })

<?
$ctx->{mruby_method}->(
    name    => "deny",
    desc    => q{Add a filter which returns <code>403 Forbidden</code> if the request matches the provided condition},
)->(sub {
?>
<pre><code>deny { ..condition.. }</code></pre>
? })

<?
$ctx->{mruby_method}->(
    name    => "redirect",
    params  => [
        { label => 'location', desc => 'Location to which the client will be redirected. Required.' },
        { label => 'status',   desc => 'Status code of the response. Default value: 302' },
    ],
    desc    => q{Add a filter which redirect the client if the request matches the provided condition},
)->(sub {
?>
<pre><code>redirect(location, status) { ..condition.. }</code></pre>
? })

<?
$ctx->{mruby_method}->(
    name    => "respond",
    params  => [
        { label => 'status', desc => 'Status code of the response. Requied.' },
        { label => 'header', desc => 'Header key-value pairs of the response. Default value: {}' },
        { label => 'body',   desc => 'Body array of the response. Default value: []' },
    ],
    desc    => q{Add a filter which returns arbitrary response if the request matches the provided condition},
)->(sub {
?>
<pre><code>respond(status, header, body) { ..condition.. }</code></pre>
? })

<?
$ctx->{mruby_method}->(
    name    => "use",
    params  => [
        { label => 'proc', desc => 'Callable object that should be applied' },
    ],
    desc    => q{Add a filter which apply the provided handler (callable object) if the request matches the provided condition},
)->(sub {
?>
<pre><code>use(proc) { ..condition.. }</code></pre>
? })

<h2 id="matching-methods" class="section-head">Matching Methods</h2>

<p>
In condition blocks, you can use helpful methods which return particular string values of the request.
Matching methods can only be used in condition block of the ACL methods.
</p>

<?
$ctx->{mruby_method}->(
    name    => "addr",
    params  => [
        { label => 'forwarded', desc => 'If true, use X-Forwarded-For header as the address if it exists. Default value: true' },
    ],
    desc    => q{ Returns the remote IP address of the request},
)->(sub {
?>
<pre><code>addr(forwarded)</code></pre>
? })

<?
$ctx->{mruby_method}->(
    name    => "path",
    desc    => q{ Returns the requested path string of the request},
)->(sub {
?>
<pre><code>path()</code></pre>
? })

<?
$ctx->{mruby_method}->(
    name    => "method",
    desc    => q{ Returns the HTTP method of the request},
)->(sub {
?>
<pre><code>method()</code></pre>
? })

<?
$ctx->{mruby_method}->(
    name    => "header",
    params  => [
        { label => 'name', desc => 'Case-insensitive header name. Requied.' },
    ],
    desc    => q{ Returns the header value of the request associated with the provided name},
)->(sub {
?>
<pre><code>header(name)</code></pre>
? })

<?
$ctx->{mruby_method}->(
    name    => "user_agent",
    desc    => q{ Shortcut for header("user-agent")},
)->(sub {
?>
<pre><code>user_agent()</code></pre>
? })

<h2 id="caution" class="section-head">Caution</h2>

<p>
To avoid miss-configuring access control, there are some rules in using <code>acl</code> method.
<ul>
<li><code>acl</code> method can be called only once in each handler configuration</li>
<li>If <code>acl</code> method is used, the evaluation result of the configuration is exactly equals to the return value of <code>acl</code> method</li>
</ul>
If a configuration violates these rules, the server will detect it and abort with error message.
</p>

<p>
For example, both of the following examples are violating the rules above, so the server will abort.
</p>

<?= $ctx->{example}->('Miss-Configuration Example 1', <<'EOT');
paths:
  "/":
    mruby.handler: |
      acl {    # this block will be ignored too!
        allow { addr == "127.0.0.1" }
      }
      acl {
        deny
      }
    file.dir: /path/to/doc_root
EOT
?>

<?= $ctx->{example}->('Miss-Configuration Example 2', <<'EOT');
paths:
  "/":
    mruby.handler: |
      acl {    # this block will be ignored!
        allow { addr == "127.0.0.1" }
        deny
      }
      proc {|env| [399, {}, []}
    file.dir: /path/to/doc_root
EOT
?>

<p>
You can correct these like the following:
</p>

<?= $ctx->{example}->('Valid Configuration Example', <<'EOT');
paths:
  "/":
    mruby.handler: |
      acl {
        allow { addr == "127.0.0.1" }
        deny
      }
    file.dir: /path/to/doc_root
EOT
?>

? })
