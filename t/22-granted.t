use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 4;
use Test::Mojo;
use Test::Differences;
use YAML::XS qw( Dump );

my $t = Test::Mojo->new('PlugAuth');
$t->get_ok('/'); # creates $t->ua
my $port = eval { $t->ua->server->url->port } // $t->ua->app_url->port;

$t->get_ok("http://primus:spark\@localhost:$port/grant")
  ->status_is(200);

my $expected = [
  '/user/#u (change_password): #u',
  '/torpedo/photon (fire): kirk',
  '#/xyz (pdq): grimlock',
  '/grant (accounts): primus',
];

eq_or_diff Dump($t->tx->res->json), Dump($expected), 'GET /grant';

