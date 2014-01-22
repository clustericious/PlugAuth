use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 95;
use Test::Mojo;
use Mojo::JSON;
use Test::Differences;

sub json($) {
    ( { 'Content-Type' => 'application/json' }, Mojo::JSON->new->encode(shift) );
}

my $t = Test::Mojo->new('PlugAuth');
$t->get_ok('/'); # creates $t->ua
my $port = eval { $t->ua->server->url->port } // $t->ua->app_url->port;

$t->get_ok("http://Primus:spark\@localhost:$port/auth")
  ->status_is(200);

  $t->get_ok("http://primus:spark\@localhost:$port/auth")
  ->status_is(200);
  
$t->get_ok("http://oPtimus:matrix\@localhost:$port/auth")
  ->status_is(200);

$t->get_ok("http://Primus:bogus\@localhost:$port/auth")
  ->status_is(403);

$t->get_ok("http://oPtimus:bogus\@localhost:$port/auth")
  ->status_is(403);

$t->get_ok('/group')
  ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( group1 group2 )], 'group = group1, group2';

$t->get_ok('/user')
  ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( optimus primus )], 'user = optimus, primus';

$t->get_ok("/groups/opTimus")
  ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( group1 group2 optimus )], 'group optimus = group1, group2, optimus';

$t->get_ok("/users/grouP1")
  ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( optimus )], 'users group1 = optimus';

$t->get_ok('/users/groUp2')
  ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( optimus primus )], 'users group2 = optimus, primus';

$t->get_ok('/authz/user/optiMus/open/matrix')
  ->status_is(403);
$t->post_ok("http://PRimus:spark\@localhost:$port/grant/optImus/open/matrix")
  ->status_is(200);
$t->get_ok('/authz/user/optiMus/open/matrix')
  ->status_is(200);
$t->delete_ok("http://prIMus:spark\@localhost:$port/grant/optIMus/open/matrix")
  ->status_is(200);

$t->get_ok('/authz/resources/PRimUS/accounts/.*')
  ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( / /user )], 'authz/resources/primus/accounts/.* = /, /user';

$t->get_ok("http://gRiMlOcK:foo\@localhost:$port/auth")
  ->status_is(403);

$t->post_ok("http://prImUs:spark\@localhost:$port/user", json { user => 'GrImLoCk', password => 'foo' })
  ->status_is(200);

$t->get_ok("/user")
  ->status_is(200);

ok scalar(grep { $_ eq 'grimlock' } @{ $t->tx->res->json }), 'created grimlock';

$t->get_ok("http://gRiMlOcK:foo\@localhost:$port/auth")
  ->status_is(200);

$t->delete_ok("http://prIMUs:spark\@localhost:$port/user/grimLOCK")
  ->status_is(200);
  
$t->get_ok("/user")
  ->status_is(200);

ok !scalar(grep { $_ eq 'grimlock' } @{ $t->tx->res->json }), 'deleted grimlock';

$t->get_ok("http://gRiMlOcK:foo\@localhost:$port/auth")
  ->status_is(403);

$t->get_ok("/users/autobot")
  ->status_is(404);
  
$t->post_ok("http://pRIMUs:spark\@localhost:$port/group", json { group => 'autoBot', users => 'priMUS,optiMUS' })
  ->status_is(200);

$t->get_ok("/users/autObot")
  ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( optimus primus )], 'users autobot = optimus, primus';

$t->post_ok("http://primus:spark\@localhost:$port/group/AutoboT", json { users => 'OPtiMUS' })
  ->status_is(200);

$t->get_ok("/users/auTObot")
  ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( optimus )], 'users autobot = optimus';
  
$t->delete_ok("http://primus:spark\@localhost:$port/group/autoboT")
  ->status_is(200);

$t->get_ok("/users/AUTObot")
  ->status_is(404);

$t->post_ok("http://primus:spark\@localhost:$port/user/opTIMus", json { password => 'matrix2' })
  ->status_is(200);

$t->get_ok("http://OPTimuS:matrix2\@localhost:$port/auth")
  ->status_is(200);

$t->get_ok("http://OPTimuS:matrix\@localhost:$port/auth")
  ->status_is(403);

$t->post_ok("http://primus:spark\@localhost:$port/group", json { group => 'Xornop', users => '' })
  ->status_is(200);

$t->get_ok("/users/xOrnop")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( )], 'xor = ""';

$t->post_ok("http://primus:spark\@localhost:$port/group/xoRnop", json { users => 'pRiMuS' })
  ->status_is(200);

$t->get_ok("/users/xOrnop")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( primus )], 'xor = primus';

$t->post_ok("http://primus:spark\@localhost:$port/group/xorNop/optIMUS")
  ->status_is(200);

$t->get_ok("/users/xOrnop")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( primus optimus )], 'xor = primus, optimus';

$t->delete_ok("http://primus:spark\@localhost:$port/group/xornOp/PrImus")
  ->status_is(200);

$t->get_ok("/users/xornoP")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( optimus )], 'xor = optimus';
