use strict;
use inc::Module::Install;

name          'Net-FastCGI';
perl_version  '5.006';
all_from      'lib/Net/FastCGI.pm';
repository    'http://github.com/chansen/p5-net-fastcgi';

requires      'Carp'             => '0';
requires      'Exporter'         => '0';

test_requires 'Test::More'       => '0.47';
test_requires 'Test::Exception'  => '0';
test_requires 'Test::HexString'  => '0';

tests 't/*.t t/*/*.t';

WriteAll;

