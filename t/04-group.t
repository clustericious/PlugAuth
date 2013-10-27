use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 4;
use Test::Mojo;

my $t = Test::Mojo->new('PlugAuth');

$t->get_ok('/'); # creates $t->ua

my $port = eval { $t->ua->server->url->port } // $t->ua->app_url->port;

$t->get_ok("http://localhost:$port/group")
    ->status_is(200)
    ->json_is('', [
        'peanuts',
        'public',
        'superuser',
    ], 'full sorted group list');

1;

