use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 21;
use Test::Mojo;

my $t = Test::Mojo->new('PlugAuth');

$t->get_ok('/'); # creates $t->ua

my $port = $t->ua->app_url->port;

sub json($) {
  ( { 'Content-Type' => 'application/json' }, Mojo::JSON->new->encode(shift) );
}

# double check initial password for optimus
$t->get_ok("http://optimus:optimus\@localhost:$port/auth")
  ->status_is(200);

# double check initial password for primus (super user)
$t->get_ok("http://primus:primus\@localhost:$port/auth")
  ->status_is(200);

# attempt to change password of optimus without credentials (fails)
$t->post_ok("http://localhost:$port/user/optimus", json { password => 'foo' } )
  ->status_is(401);

# double check password of optimus has not changed
$t->get_ok("http://optimus:optimus\@localhost:$port/auth")
  ->status_is(200);

# empty password returns error
$t->post_ok("http://primus:primus\@localhost:$port/user/optimus")
  ->status_is(403);

# double check password of optimus has not changed
$t->get_ok("http://optimus:optimus\@localhost:$port/auth")
  ->status_is(200);

# attempt to change password of optimus with primus (super user)
$t->post_ok("http://primus:primus\@localhost:$port/user/optimus", json { password => 'matrix' } )
  ->status_is(200);

# double check that old credentials for optimus no longer work
$t->get_ok("http://optimus:optimus\@localhost:$port/auth")
  ->status_is(403);

# double check that new credentials for optimus DOES work
$t->get_ok("http://optimus:matrix\@localhost:$port/auth")
  ->status_is(200);

# bogus user returns error
$t->post_ok("http://primus:primus\@localhost:$port/user/bogus", json { password => 'bar' } )
  ->status_is(403);
