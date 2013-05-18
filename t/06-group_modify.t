use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 104;
use Test::Mojo;
use Mojo::JSON;
use Test::Differences;

my $t = Test::Mojo->new('PlugAuth');

$t->get_ok('/'); # creates $t->ua

my $port = $t->ua->app_url->port;

$t->app->config->{plug_auth} = { url => "http://localhost:$port" };

sub json($) {
    ( { 'Content-Type' => 'application/json' }, Mojo::JSON->new->encode(shift) );
}

# creating a group without credentials should return a 401
$t->post_ok("http://localhost:$port/group", json { group => 'group1' } )
    ->status_is(401)
    ->content_is("auth required", "attempt to create group without credentials");

$t->get_ok("http://localhost:$port/group");
is grep(/^group1$/, @{ $t->tx->res->json }), 0, "group1 was not created";

# creating a group with bogus credentials should return 403
$t->post_ok("http://bogus:passs\@localhost:$port/group", json { group => 'group2' } )
    ->status_is(401)
    ->content_is("authentication failure", "attempt to create with bogus credentials");

$t->get_ok("http://localhost:$port/group");
is grep(/^group2$/, @{ $t->tx->res->json }), 0, "group2 was not created";

# create an empty group
$t->post_ok("http://huffer:snoopy\@localhost:$port/group", json { group => 'group3' } )
    ->status_is(200)
    ->content_is("ok", "create group3 (empty)");

$t->get_ok("http://localhost:$port/group");
is grep(/^group3$/, @{ $t->tx->res->json }), 1, "group3 was created";

$t->get_ok("http://localhost:$port/users/group3")
    ->json_is('', [], "group3 is empty");

do {
  my $args = {};
  $t->app->once(create_group => sub { my $e = shift; $args = shift });

  # create an group with four users
  $t->post_ok("http://huffer:snoopy\@localhost:$port/group", json { group => 'group4', users => 'optimus,rodimus,huffer,grimlock' } )
    ->status_is(200)
    ->content_is("ok", "create group4 (optimus,rodimus,huffer,grimlock)");
    
  is $args->{admin}, 'huffer', 'admin = huffer';
  is $args->{group}, 'group4', 'group = group4';
  is $args->{users}, 'optimus,rodimus,huffer,grimlock', 'users = optimus,rodimus,huffer,grimlock';
};

$t->get_ok("http://localhost:$port/group");
is grep(/^group4$/, @{ $t->tx->res->json }), 1, "group4 was created";

$t->get_ok("http://localhost:$port/users/group4");

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( optimus rodimus huffer grimlock )], 'group4 is not empty';
    
# remove a group
$t->get_ok("http://localhost:$port/group");
is grep(/^group5$/, @{ $t->tx->res->json }), 1, "group5 exists";

do {
  my $args = {};
  $t->app->once(delete_group => sub { my $e = shift; $args = shift });

  $t->delete_ok("http://huffer:snoopy\@localhost:$port/group/group5")
    ->status_is(200)
    ->content_is("ok", "delete group5");

  is $args->{admin}, 'huffer', 'admin = huffer';
  is $args->{group}, 'group5', 'group = group5';
};

$t->get_ok("http://localhost:$port/group");
is grep(/^group5$/, @{ $t->tx->res->json }), 0, "group5 deleted";

# remove a non existent group
$t->get_ok("http://localhost:$port/group");
is grep(/^group6/, @{ $t->tx->res->json }), 0, "group6 does not exist";

$t->delete_ok("http://huffer:snoopy\@localhost:$port/group/group6")
    ->status_is(404)
    ->content_is("not ok", "cannot delete non existent group");

$t->get_ok("http://localhost:$port/group");
is grep(/^group6/, @{ $t->tx->res->json }), 0, "group6 (still) does not exist";

# create an already existing group
$t->get_ok("http://localhost:$port/group");
is grep(/^group7/, @{ $t->tx->res->json }), 1, "group7 exists";

$t->post_ok("http://huffer:snoopy\@localhost:$port/group", json { group => 'group7', users => 'foo,bar,baz' })
    ->status_is(403)
    ->content_is('not ok', 'cannot create already existing group7');

$t->get_ok("http://localhost:$port/group");
is grep(/^group7/, @{ $t->tx->res->json }), 1, "group7 (still) exists";

$t->get_ok("http://huffer:snoopy\@localhost:$port/users/group7")
    ->status_is(200);

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( grimlock rodimus )], 'group7 is [grimlock,rodimus]';

# creating a group with a real user but bad password
$t->post_ok("http://huffer:passs\@localhost:$port/group", json { group => 'group8' } )
    ->status_is(401)
    ->content_is("authentication failure", "attempt to create with bogus credentials");

$t->get_ok("http://localhost:$port/group");
is grep(/^group8$/, @{ $t->tx->res->json }), 0, "group8 was not created";

# change the user membership of an existing group
$t->get_ok("http://localhost:$port/users/group9");

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( nightbeat starscream soundwave )], "group9 is [ nightbeat,starscream,soundwave ]";

do {
  my $args = {};
  $t->app->once(update_group => sub { my $e = shift; $args = shift });

  $t->post_ok("http://huffer:snoopy\@localhost:$port/group/group9", json { users => "optimus,rodimus,huffer,grimlock" })
    ->status_is(200)
    ->content_is("ok");
    
  is $args->{admin}, 'huffer', 'admin = huffer';
  is $args->{group}, 'group9', 'group = group9';
  is $args->{users}, "optimus,rodimus,huffer,grimlock", 'users = optimus,rodimus,huffer,grimlock';
};

$t->get_ok("http://localhost:$port/users/group9");

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( optimus rodimus huffer grimlock )], 'group9 is [ optimus,rodimus,huffer,grimlock ]';
    
# remove all users from a group
$t->get_ok("http://localhost:$port/users/group10");

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( nightbeat starscream soundwave )], "group10 is [ nightbeat,starscream,soundwave ]";

$t->post_ok("http://huffer:snoopy\@localhost:$port/group/group10", json { users => '' })
    ->status_is(200)
    ->content_is("ok");

$t->get_ok("http://localhost:$port/users/group10")
    ->json_is('', [], "group10 is empty");

# change user membership of an existing group with an invalid username
$t->get_ok("http://localhost:$port/users/group11");

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( nightbeat starscream soundwave )], "group11 is [ nightbeat,starscream,soundwave ]";

$t->post_ok("http://huffer:snoopy\@localhost:$port/group/group11", json { users => "optimus,foo,bar,baz" })
    ->status_is(200)
    ->content_is("ok");

$t->get_ok("http://localhost:$port/users/group11")
    ->json_is('', [sort qw( optimus )], "group11 is [ optimus ]");

# change user membership of a non existent group
$t->get_ok("http://localhost:$port/group");
is grep(/^group12$/, @{ $t->tx->res->json }), 0, "no group 12";

$t->post_ok("http://huffer:snoopy\@localhost:$port/group/group12", json { users => "optimus,rodimus,huffer,grimlock" })
    ->status_is(404)
    ->content_is("not ok");

$t->get_ok("http://localhost:$port/group");
is grep(/^group12$/, @{ $t->tx->res->json }), 0, "(still) no group 12";

# change user membership of an existing group with bad credentials
$t->get_ok("http://localhost:$port/users/group14");

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( nightbeat starscream soundwave )], "group14 is [ nightbeat,starscream,soundwave ]";

$t->post_ok("http://huffer:bogus\@localhost:$port/group/group14", json { users => "optimus,rodimus,huffer,grimlock" })
    ->status_is(401)
    ->content_is("authentication failure");

$t->get_ok("http://localhost:$port/users/group14");

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( nightbeat starscream soundwave )], "group14 is (still) [ nightbeat,starscream,soundwave ]";

# update group without providing user field
$t->get_ok("http://localhost:$port/users/group15");

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( nightbeat starscream soundwave )], "group15 is [ nightbeat,starscream,soundwave ]";

$t->post_ok("http://huffer:snoopy\@localhost:$port/group/group15", json {})
    ->status_is(200)
    ->content_is("ok");

$t->get_ok("http://localhost:$port/users/group15");

eq_or_diff [sort @{ $t->tx->res->json }], [sort qw( nightbeat starscream soundwave )], "group15 is (still) [ nightbeat,starscream,soundwave ]";

1;
