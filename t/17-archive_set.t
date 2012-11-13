use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 7;
use Test::Mojo;
use Mojo::JSON;
use Test::Differences;

my $t = Test::Mojo->new('PlugAuth');

$t->get_ok('/'); # creates $t->ua

my $port = $t->ua->app_url->port;

$t->get_ok("http://localhost:$port/authz/resources/grimlock/view//archiveset/\\d+")
  ->status_is(200);

eq_or_diff $t->tx->res->json, [qw( /archiveset/1 /archiveset/3 )], "grimlock";

$t->get_ok("http://localhost:$port/authz/resources/prime/view//archiveset/\\d+")
  ->status_is(200);

eq_or_diff $t->tx->res->json, [qw( /archiveset/2 )], "prime";

