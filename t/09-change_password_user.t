use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 24;
use Test::Mojo;
use JSON::MaybeXS qw( encode_json );

my $t = Test::Mojo->new('PlugAuth');

my $port = eval { $t->ua->server->url->port } // $t->ua->app_url->port;

sub json($) {
  ( { 'Content-Type' => 'application/json' }, encode_json(shift) );
}

# double check initial password for optimus
$t->get_ok("http://optimus:optimus\@localhost:$port/auth")
  ->status_is(200);

# double check initial password for primus (super user)
$t->get_ok("http://primus:primus\@localhost:$port/auth")
  ->status_is(200);

# one user can't change another's password
$t->post_ok("http://primus:primus\@localhost:$port/user/optimus", json { password => 'foo' } )
  ->status_is(403);

# one user can't change another's password
$t->post_ok("http://optimus:optimus\@localhost:$port/user/primus", json { password => 'foo' } )
  ->status_is(403);

# passwords have not changed
$t->get_ok("http://optimus:optimus\@localhost:$port/auth")
  ->status_is(200);

$t->get_ok("http://primus:primus\@localhost:$port/auth")
  ->status_is(200);

# each user can change his/her own password
$t->post_ok("http://primus:primus\@localhost:$port/user/primus", json { password => 'iamagod' } )
  ->status_is(200);

$t->post_ok("http://optimus:optimus\@localhost:$port/user/optimus", json { password => 'matrix' } )
  ->status_is(200);

# passwords have changed
$t->get_ok("http://optimus:matrix\@localhost:$port/auth")
  ->status_is(200);

$t->get_ok("http://primus:iamagod\@localhost:$port/auth")
  ->status_is(200);

$t->get_ok("http://optimus:optimus\@localhost:$port/auth")
  ->status_is(403);

$t->get_ok("http://primus:primus\@localhost:$port/auth")
  ->status_is(403);
