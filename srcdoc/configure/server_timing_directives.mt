? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Server Timing Directives")->(sub {

<p>
The server timing handler turns on the <a href="https://www.w3.org/TR/server-timing/">Server Timing</a> feature.
This document describes the configuration directives of the handler.
</p>

? $ctx->{directive_list}->()->(sub {

<?
my $access_log_ext_link = sub {
    my $name = shift;
    return $_mt->filter(sub {
        "<a href=\"configure/access_log_directives.html#$name\"><code>$name</code></a>"
    })->(sub {});
};
$ctx->{directive}->(
    name    => "server-timing",
    levels  => [ qw(global host path extension) ],
    default => 'OFF',
    since   => '2.3',
    desc    => <<'EOT',
A flag indicating how <code>server-timing</code> header and trailer should be served.
EOT
)->(sub {
?>

<p>
If the value is <code>ON</code>, H2O adds the <code>server-timing</code> header and trailer (if possible) to the response. The header is always added, but the trailer isn't if all of the following conditions are met.
<ul>
<li>The protocol used for the request is HTTP/1.1</li>
<li><code>transfer encoding</code> of the response is not <code>chunked</code></li>
</ul>
</p>

<p>
If the value is <code>ENFORCE</code>, H2O forces the response to use chunked encoding by removing <code>content-length</code> header.
</p>

<p>
If the value is <code>OFF</code>, the feature is disabled.
</p>

<p>
The <code>server-timing</code> header and trailer includes the following metrics. For now, all metrics have the <code>dur</code> attribute whose values are exactly equal to one of the Access Log Extensions with similar names. To get the meaning of each <code>dur</code> attribute, see <a href="https://h2o.examp1e.net/configure/access_log_directives.html#access-log"><code>access-log</code></a>.

<table>
    <caption>Header Metrics</caption>
    <tr>
        <th>Name</th>
        <th>Log Extension</th>
    </tr>
    <tr>
        <td><code>connect</code></td>
        <td><? $access_log_ext_link->('connect-time') ?></td>
    </tr>
    <tr>
        <td><code>request-header</code></td>
        <td><? $access_log_ext_link->('request-header-time') ?></td>
    </tr>
    <tr>
        <td><code>request-body</code></td>
        <td><? $access_log_ext_link->('request-body-time') ?></td>
    </tr>
    <tr>
        <td><code>request-total</code></td>
        <td><? $access_log_ext_link->('request-total-time') ?></td>
    </tr>
    <tr>
        <td><code>process</code></td>
        <td><? $access_log_ext_link->('process-time') ?></td>
    </tr>
    <tr>
        <td><code>proxy.idle</code></td>
        <td><? $access_log_ext_link->('proxy.idle-time') ?></td>
    </tr>
    <tr>
        <td><code>proxy.connect</code></td>
        <td><? $access_log_ext_link->('proxy.connect-time') ?></td>
    </tr>
    <tr>
        <td><code>proxy.request</code></td>
        <td><? $access_log_ext_link->('proxy.request-time') ?></td>
    </tr>
    <tr>
        <td><code>proxy.process</code></td>
        <td><? $access_log_ext_link->('proxy.process-time') ?></td>
    </tr>
</table>

<table>
    <caption>Trailer Metrics</caption>
    <tr>
        <th>Name</th>
        <th>Log Extension</th>
    </tr>
    <tr>
        <td><code>response</code></td>
        <td><? $access_log_ext_link->('response-time') ?></td>
    </tr>
    <tr>
        <td><code>total</code></td>
        <td><? $access_log_ext_link->('total-time') ?> / <? $access_log_ext_link->('duration') ?></td>
    </tr>
    <tr>
        <td><code>proxy.response</code></td>
        <td><? $access_log_ext_link->('proxy.response-time') ?></td>
    </tr>
    <tr>
        <td><code>proxy.total</code></td>
        <td><? $access_log_ext_link->('proxy.total-time') ?></td>
    </tr>
</table>
</p>

? })

? })

? })
