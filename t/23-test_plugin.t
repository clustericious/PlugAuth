use strict;
use warnings;
use FindBin ();
BEGIN { 
  $ENV{PLUGAUTH_CONF_DIR} = "$FindBin::Bin/data/23";
  require "$FindBin::Bin/etc/setup.pl" 
}
use Test::More tests => 22;
use Test::Mojo;
use Mojo::JSON;
use Test::Differences;
use YAML::XS qw( Dump );

my $t = Test::Mojo->new('PlugAuth');
$t->get_ok('/'); # creates $t->ua
my $port = $t->ua->app_url->port;

$t->get_ok("http://primus:spark\@localhost:$port/auth")
  ->status_is(403);

$t->post_ok('/test/setup/basic')
  ->status_is(200);

$t->get_ok("http://primus:spark\@localhost:$port/auth")
  ->status_is(200);

$t->get_ok("http://optimus:matrix\@localhost:$port/auth")
  ->status_is(200);

$t->get_ok("/users/admin")
  ->status_is(200)
  ->json_is('/0', 'primus');

$t->get_ok("/authz/user/primus/accounts/user")
  ->status_is(200);

$t->get_ok("/authz/user/optimus/accounts/user")
  ->status_is(403);

$t->get_ok("http://primus:spark\@localhost:$port/grant")
  ->status_is(200);

$t->post_ok('/test/setup/reset')
  ->status_is(200);

$t->get_ok("http://primus:spark\@localhost:$port/auth")
  ->status_is(403);
