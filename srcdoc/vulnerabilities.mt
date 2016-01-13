? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Vulnerabilities")->(sub {

<h3 id="CVE-2016-1133">CVE-2016-1133 (Response Splitting)</h3>

<div>
Date: Jan. 13, 2015<br>
CVE-ID: <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1133">CVE-2016-1133</a>
</div>

<p>
H2O up to version 1.6.1 / 1.7.0-beta2 contains a flaw in the redirect handler.
When <code><a href="https://h2o.examp1e.net/configure/redirect_directives.html#redirect">redirect</a></code> directive is used, this flaw allows a remote attacker to inject response headers into an HTTP redirect response.
H2O <a href="https://github.com/h2o/h2o/releases/tag/v1.6.2">version 1.6.2</a> has been released to address this vulnerability.
Users are advised to upgrade their servers immediately.
</p>
<p>
See also: <a href="https://github.com/h2o/h2o/issues/682">#682</a>, <a href="https://github.com/h2o/h2o/issues/684">#684</a>
</p>

<h3 id="CVE-2015-5638">CVE-2015-5638 (Directory Traversal)</h3>

<div>
Date: Sep. 16, 2015<br>
CVE-ID: <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5638">CVE-2015-5638</a>
</div>

<p>
H2O up to version 1.4.4 / 1.5.0-beta1 contains a flaw in its URL normalization logic.
When <code><a href="configure/file_directives.html#file.dir">file.dir</a></code> directive is used, this flaw allows a remote attacker to retrieve arbitrary files that exist outside the directory specified by the directive.
H2O <a href="https://github.com/h2o/h2o/releases/tag/v1.4.5">version 1.4.5</a> and <a href="https://github.com/h2o/h2o/releases/tag/v1.5.0-beta2">version 1.5.0-beta2</a> have been released to address this vulnerability.
Users are advised to upgrade their servers immediately (the fixed version is now available as FreeBSD Port / Homebrew as well).
</p>
<p>
The vulnerability was reported by: Yusuke OSUMI.
</p>

<div>
<p>
(Japanese translation follows)
</p>
<p>
H2O（バージョン1.4.4以前および1.5.0-beta1以前）のURL正規化処理には不備があり、この結果、<code><a href="configure/file_directives.html#file.dir">file.dir</a></code>ディレクティブを使用している場合、同ディレクティブで指定されたディレクトリ以外に存在する任意のファイルをリモートの攻撃者が取得できるという脆弱性が存在します。
</p>
<p>
この脆弱性を修正したH2O<a href="https://github.com/h2o/h2o/releases/tag/v1.4.5">バージョン1.4.5</a>および<a href="https://github.com/h2o/h2o/releases/tag/v1.5.0-beta2">バージョン1.5.0-beta2</a>がリリースされています。
</p>
<p>
ユーザの皆様におかれましては、直ちに最新版にアップグレードしていただきますようご案内申し上げます。
</p>
<p>
本脆弱性は大角 祐介氏によって報告されました。この場を借りて氏に御礼申し上げます。
</p>
</div>

? })
