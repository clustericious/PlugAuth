use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 16;
use Test::Mojo;
use Test::Differences;

my $t = Test::Mojo->new('PlugAuth');

$t->get_ok('/'); # creates $t->ua

my $port = eval { $t->ua->server->url->port } // $t->ua->app_url->port;

$t->get_ok("http://localhost:$port/user")
    ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( bar charliebrown deckard elmer linus this.user.has.a.dot@dot.com thor )], 'full user list';
    
$t->get_ok("http://localhost:$port/users/peanuts")
    ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( charliebrown linus )], 'list of users belonging to peanuts';
    
$t->get_ok("http://localhost:$port/users/public")
    ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( bar charliebrown deckard elmer linus this.user.has.a.dot@dot.com thor )], 'list of users belonging to public';
    
$t->get_ok("http://localhost:$port/users/superuser")
    ->status_is(200)
    ->json_is('', [
        'thor',
    ], 'list of users belonging to superuser');

$t->get_ok("http://localhost:$port/users/bogus")
    ->status_is(404)
    ->content_is('not ok');

1;
