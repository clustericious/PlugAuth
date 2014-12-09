use strict;
use warnings;
use FindBin ();
BEGIN { 
  $ENV{PLUGAUTH_CONF_DIR} = "$FindBin::Bin/data/24";
  require "$FindBin::Bin/etc/setup.pl" 
}
use Test::More tests => 10;
use Test::Mojo;
use Test::Differences;
use YAML::XS qw( Dump );

my $t = Test::Mojo->new('PlugAuth');

$t->post_ok('/test/setup/basic');
$t->post_ok('/grant/optimus/view/service/filefeed')->status_is(200);

$t->get_ok('/authz/user/optimus/view/service/filefeed')->status_is(200);
$t->get_ok('/authz/user/optimus/view/service/filefeed/foo/bar/baz.png')->status_is(200);

$t->get_ok('/grant');

$t->get_ok('/authz/resources/optimus/view/.*');

eq_or_diff Dump($t->tx->res->json), Dump(['/service/filefeed']), 'avoid autovivification';
