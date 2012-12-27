use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 12;
use Test::Mojo;
use Mojo::JSON;
use Test::Differences;

my $t = Test::Mojo->new('PlugAuth');

$t->get_ok('/authz/user/primus/accounts/foo/bar/baz')
  ->status_is(200);
$t->get_ok('/authz/user/optimus/accounts/foo/bar/baz')
  ->status_is(403);

$t->get_ok('/authz/user/primus/accounts/')
  ->status_is(200);
$t->get_ok('/authz/user/optimus/accounts/')
  ->status_is(403);

$t->get_ok('/authz/user/primus/accounts')
  ->status_is(200);
$t->get_ok('/authz/user/optimus/accounts')
  ->status_is(403);
