use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 51;
use Test::Mojo;

my $logdir = "$FindBin::Bin/log";
-d $logdir or mkdir $logdir or die "couldn't make $logdir : $!";

my $t = Test::Mojo->new("PlugAuth");

$t->get_ok('/')
  ->status_is(200)
  ->content_like(qr/welcome/, 'welcome message!');

my $port = eval { $t->ua->server->url->port } // $t->ua->app_url->port;

# missing user + pw
$t->get_ok('/auth')
  ->status_is(401)
  ->content_like(qr[authenticate], 'got authenticate header');

# good user
$t->get_ok("http://charliebrown:snoopy\@localhost:$port/auth")
  ->status_is(200)
  ->content_is("ok", 'auth succeeded');

# good user with funky name
my $url = Mojo::URL->new("http://localhost:$port/auth");
$url->userinfo("this.user.has.a.dot\@dot.com:fudd");
$t->get_ok($url)
  ->status_is(200)
  ->content_is("ok", 'auth succeeded');

# good user in two places
$t->get_ok("http://elmer:fudd\@localhost:$port/auth")
  ->status_is(200)
  ->content_is("ok", 'auth succeeded');

$t->get_ok("http://elmer:glue\@localhost:$port/auth")
  ->status_is(200)
  ->content_is("ok", 'auth succeeded');

# unknown user
$t->get_ok("http://charliebrown:snoopy\@localhost:$port/auth")
  ->status_is(200)
  ->content_is("ok", 'auth succeeded');

# bad pw
$t->get_ok("http://charliebrown:badpass\@localhost:$port/auth")
  ->status_is(403)
  ->content_is("not ok", 'auth failed');

# missing pw
$t->get_ok("http://charliebrown\@localhost:$port/auth")
  ->status_is(403)
  ->content_is("not ok", 'auth failed');

# check for trusted host
$t->get_ok('/host/127.9.9.9/trusted')
  ->status_is(200)
  ->content_is("ok", "trusted host");

$t->get_ok('/host/123.123.123.123/trusted')
  ->status_is(403)
  ->content_is("not ok", "untrusted host");

# good user with mixed case
$t->get_ok("http://CharlieBrown:snoopy\@localhost:$port/auth")
  ->status_is(200)
  ->content_is("ok", 'case insensative username');

# bad pw
$t->get_ok("http://CharlieBrown:badpass\@localhost:$port/auth")
  ->status_is(403)
  ->content_is("not ok", 'case insensative username auth failed');

# apache md5
$t->get_ok("http://deckard:androidsdream\@localhost:$port/auth")
  ->status_is(200)
  ->content_is("ok", "apache md5 password is okay");

$t->get_ok("http://deckard:androidsdreamx\@localhost:$port/auth")
  ->status_is(403)
  ->content_is("not ok", "bad apache md5 password is not okay");

# unix md5
$t->get_ok("http://bar:foo\@localhost:$port/auth")
  ->status_is(200)
  ->content_is("ok", "unix md5 password is okay");

$t->get_ok("http://bar:foox\@localhost:$port/auth")
  ->status_is(403)
  ->content_is("not ok", "bad unix md5 password is not okay");



1;


