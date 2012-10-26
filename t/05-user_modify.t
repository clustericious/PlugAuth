use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 74;
use Test::Mojo;
use Mojo::JSON;

my $t = Test::Mojo->new('PlugAuth');

$t->get_ok('/'); # creates $t->ua

my $port = $t->ua->app_url->port;

$t->app->config->simple_auth->{url} = "http://localhost:$port";

sub json($) {
    ( { 'Content-Type' => 'application/json' }, Mojo::JSON->new->encode(shift) );
}

# creating a user without credentials should return a 401
$t->post_ok("http://localhost:$port/user", json { user => 'donald', password => 'duck' } )
    ->status_is(401)
    ->content_is("auth required", "attempt to create a user without credentials");

# creating a user with bogus credentials should return 403
$t->post_ok("http://bogus:passs\@localhost:$port/user", json { user => 'donald', password => 'duck' } )
    ->status_is(401)
    ->content_is("authentication failure", "attempt to create with bogus credentials");

# creating a user without credentials or with bogus credentials (above) should not change the
# password file
$t->get_ok("http://localhost:$port/user");
is grep(/^donald$/, @{ $t->tx->res->json }), 0, "donald was not created";

$t->get_ok("http://donald:duck\@localhost:$port/auth")
    ->status_is(403)
    ->content_is("not ok", 'auth does not work with user created without authenticating');

$t->get_ok("http://newuser:newpassword\@localhost:$port/auth")
    ->status_is(403)
    ->content_is("not ok", 'auth does not work before user created');

$t->post_ok("http://elmer:fudd\@localhost:$port/user", json { user => 'newuser' })
    ->status_is(403)
    ->content_is('not ok', 'cannot create user without a password');

$t->post_ok("http://elmer:fudd\@localhost:$port/user", json { password => 'newpassword' })
    ->status_is(403)
    ->content_is('not ok', 'cannot create user without a user');

$t->post_ok("http://elmer:fudd\@localhost:$port/user", json { user => 'newuser', password => 'newpassword' })
    ->status_is(200)
    ->content_is("ok", "created newuser");

$t->get_ok("http://newuser:newpassword\@localhost:$port/auth")
    ->status_is(200)
    ->content_is("ok", 'auth works after user created');

$t->get_ok("http://localhost:$port/user");
is grep(/^newuser$/, @{ $t->tx->res->json }), 1, "newuser was created";

# user should get added to public group which is set to *
$t->get_ok("http://localhost:$port/users/public");
is grep(/^newuser$/, @{ $t->tx->res->json }), 1, "newuser belongs to public";

$t->delete_ok("http://localhost:$port/user/thor")
    ->status_is(401)
    ->content_is("auth required", "cannot delete user without credentials");

$t->delete_ok("http://baduser:badpassword\@localhost:$port/user/thor")
    ->status_is(401)
    ->content_is("authentication failure", "cannot delete user with bad credentials");

$t->get_ok("http://localhost:$port/user");
is grep(/^thor$/, @{ $t->tx->res->json }), 1, "thor is not deleted in failed delete";

$t->get_ok("http://localhost:$port/user");
is grep(/^charliebrown$/, @{ $t->tx->res->json }), 1, "charlie brown exists before he is deleted";

$t->get_ok("http://charliebrown:snoopy\@localhost:$port/auth")
    ->status_is(200)
    ->content_is("ok", "auth works before user is deleted");

$t->get_ok("http://localhost:$port/user");
is grep(/^charliebrown$/, @{ $t->tx->res->json }), 1, "charlie brown not deleted in failed delete";

$t->delete_ok("http://elmer:fudd\@localhost:$port/user/charliebrown")
    ->status_is(200)
    ->content_is("ok", "delete user");

$t->get_ok("http://charliebrown:snoopy\@localhost:$port/auth")
    ->status_is(403)
    ->content_is("not ok", "auth fails after user is deleted");

$t->get_ok("http://localhost:$port/user");
is grep(/^charliebrown$/, @{ $t->tx->res->json }), 0, "charlie brown does not exists after he is deleted";

# deleted users should be removed from the public group which  is set to *
$t->get_ok("http://localhost:$port/users/public");
is grep(/^charliebrown$/, @{ $t->tx->res->json }), 0, "charlie brown is not in the public group";

$t->get_ok("http://nEwuSer1:newpassword\@localhost:$port/auth")
    ->status_is(403)
    ->content_is("not ok", 'mixed case user password auth before create');

$t->post_ok("http://elmer:fudd\@localhost:$port/user", json { user => 'NewUser1', password => 'newpassword' })
    ->status_is(200)
    ->content_is("ok", "mixed case user");

$t->get_ok("http://nEwuSer1:newpassword\@localhost:$port/auth")
    ->status_is(200)
    ->content_is("ok", 'mixed case user password auth after create');

$t->get_ok("http://nEwuSer1:badpassword\@localhost:$port/auth")
    ->status_is(403)
    ->content_is("not ok", 'mixed case user password auth after create bad password');

$t->delete_ok("http://elmer:fudd\@localhost:$port/user/nEwuSeR1")
    ->status_is(200)
    ->content_is("ok", "mixed case user delete");

$t->get_ok("http://nEwuSer1:newpassword\@localhost:$port/auth")
    ->status_is(403)
    ->content_is("not ok", 'mixed case user password auth after delete');

1;
