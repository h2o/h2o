? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure")->(sub {

<ul style="list-style: none; font-weight: bold;">
<li><a href="configure/quick_start.html">Quick Start</a>
<li><a href="configure/command_options.html">Command Options</a>
<li>Configuration File
<ul>
<li><a href="configure/syntax_and_structure.html">Syntax and Structure</a>
</ul>
<li>Configuration Directives
<ul>
<li><a href="configure/base_directives.html">Base</a>
<li><a href="configure/http1_directives.html">HTTP/1</a>
<li><a href="configure/http2_directives.html">HTTP/2</a>
<li><a href="configure/access_log_directives.html">Access Log</a>
<li><a href="configure/compress_directives.html">Compress</a>
<li><a href="configure/errordoc_directives.html">Errordoc</a>
<li><a href="configure/expires_directives.html">Expires</a>
<li><a href="configure/fastcgi_directives.html">FastCGI</a>
<li><a href="configure/file_directives.html">File</a>
<li><a href="configure/headers_directives.html">Headers</a>
<li><a href="configure/mruby_directives.html">Mruby</a>
<li><a href="configure/proxy_directives.html">Proxy</a>
<li><a href="configure/redirect_directives.html">Redirect</a>
<li><a href="configure/reproxy_directives.html">Reproxy</a>
<li><a href="configure/status_directives.html">Status</a>
<li><a href="configure/throttle_response_directives.html">Throttle Response</a>
</ul>
</li>
<li>How-To
<ul>
<li><a href="configure/basic_auth.html">Using Basic Authentication</a></li>
<li><a href="configure/cgi.html">Using CGI</a></li>
<li><a href="configure/mruby.html">Using Mruby</a></li>
<li><a href="configure/dos_detection.html">Using DoS Detection</a></li>
<li><a href="configure/access_control.html">Access Control</a></li>
</ul>
</li>
<li><a href="https://github.com/h2o/h2o/wiki#configuration-examples" target="_blank">Configuration Examples (Wiki)</a>
</ul>

? })
