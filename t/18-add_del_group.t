use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 58;
use Test::Mojo;
use Test::Differences;

my $t = Test::Mojo->new('PlugAuth');

$t->get_ok('/'); # creates $t->ua

my $port = eval { $t->ua->server->url->port } // $t->ua->app_url->port;

# First check that the groups are right at start.
$t->get_ok("http://localhost:$port/users/full1")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( foo bar baz primus )], "at start full1 = foo bar baz";
$t->get_ok("http://localhost:$port/users/full2")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( foo bar baz primus )], "at start full2 = foo bar baz";
$t->get_ok("http://localhost:$port/users/part1")
  ->status_is(200);
eq_or_diff [@{ $t->tx->res->json }], ['foo'], "at start part1 = foo";
$t->get_ok("http://localhost:$port/users/part2")
  ->status_is(200);
eq_or_diff [@{ $t->tx->res->json }], ['baz'], "at start part2 = baz";

# next add bar to part1
$t->post_ok("http://primus:primus\@localhost:$port/group/part1/bar")
  ->status_is(200)
  ->content_is('ok');
$t->get_ok("http://localhost:$port/users/part1")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( foo bar) ], "at start part1 = foo bar";

# next add to a non-existent group
$t->post_ok("http://primus:primus\@localhost:$port/group/bogus/foo")
  ->status_is(404)
  ->content_is('not ok');
$t->get_ok("http://localhost:$port/users/bogus")
  ->status_is(404)
  ->content_is('not ok');

# add bar and baz to part2
$t->post_ok("http://primus:primus\@localhost:$port/group/part2/bar")
  ->status_is(200)
  ->content_is('ok');
$t->post_ok("http://primus:primus\@localhost:$port/group/part2/foo")
  ->status_is(200)
  ->content_is('ok');
$t->get_ok("http://localhost:$port/users/part2")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( foo bar baz) ], "at start part2 = foo bar baz";

# add foo to full1 and full2
$t->post_ok("http://primus:primus\@localhost:$port/group/full1/bar")
  ->status_is(200)
  ->content_is('ok');
$t->get_ok("http://localhost:$port/users/full1")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( foo bar baz primus) ], "at start full1 = foo bar baz primus";

$t->post_ok("http://primus:primus\@localhost:$port/group/full2/bar")
  ->status_is(200)
  ->content_is('ok');
$t->get_ok("http://localhost:$port/users/full2")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( foo bar baz primus) ], "at start full2 = foo bar baz primus";

# remove foo from full3 and full4
$t->delete_ok("http://primus:primus\@localhost:$port/group/full3/foo")
  ->status_is(200)
  ->content_is('ok');
$t->get_ok("http://localhost:$port/users/full3")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( bar baz primus) ], "at start full3 = foo bar baz primus";

$t->delete_ok("http://primus:primus\@localhost:$port/group/full4/foo")
  ->status_is(200)
  ->content_is('ok');
$t->get_ok("http://localhost:$port/users/full4")
  ->status_is(200);
eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( bar baz primus) ], "at start full4 = foo bar baz primus";
