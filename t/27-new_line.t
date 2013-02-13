use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 21;
use Test::Mojo;
use Test::Differences;

my $t = Test::Mojo->new('PlugAuth');

$t->get_ok('/'); # creates $t->ua
my $port = $t->ua->app_url->port;

sub json($) {
    ( { 'Content-Type' => 'application/json' }, Mojo::JSON->new->encode(shift) );
}

# creating a user with bogus credentials should return 403
$t->post_ok("http://primus:matrix\@localhost:$port/user", json { user => 'donald', password => 'duck' } )
  ->status_is(200);

$t->get_ok("http://primus:matrix\@localhost:$port/auth")
  ->status_is(200);

$t->get_ok("http://primus:bogus\@localhost:$port/auth")
  ->status_is(403);
  
$t->get_ok("http://donald:duck\@localhost:$port/auth")
  ->status_is(200);
  
$t->get_ok("http://optimus:matrix\@localhost:$port/auth")
  ->status_is(200);

$t->get_ok("http://unicron:chaos\@localhost:$port/auth")
  ->status_is(200);

$t->get_ok("/groups/primus")
  ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( primus public ) ];

$t->post_ok("http://primus:matrix\@localhost:$port/group", json { group => 'god', users => 'primus,unicron' })
  ->status_is(200);
  
$t->get_ok("/groups/primus")
  ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( primus public god ) ];