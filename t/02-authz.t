use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 48;
use Test::Mojo;

my $t = Test::Mojo->new("PlugAuth");

$t->get_ok('/'); # creates $t->ua

my $port = $t->ua->app_url->port;

sub _allowed {
    my $url = shift;
    $t->get_ok("http://localhost:$port/authz/$url")
        ->status_is(200)
        ->content_is("ok", "authorization succeeded for $url");
}

sub _denied {
    my $url = shift;

    my($not_used, $user, $action, $resource) = split /\//, $url;

    $t->get_ok("http://localhost:$port/authz/$url")
        ->status_is(403)
        ->content_like(qr/^unauthorized : $user cannot $action \/$resource$/, "authorization denied for $url");
}

#
# Test various privileges as given in the sample authorization files.
#
_allowed(q|user/charliebrown/kick/football|);
_allowed(q|user/CharlieBrown/kick/football|);
_allowed(q|user/linus/kick/football|);
_allowed(q|user/charliebrown/miss/football|);
 _denied(q|user/linus/miss/football|);
 _denied(q|user/Linus/miss/football|);
 _denied(q|user/elmer/kick/football|);
_allowed(q|user/thor/kick/football|);
_allowed(q|user/thor/glob/globtest|);

#
# Get a list of resources matching a regex for a particular
# user and action.
#
$t->get_ok("http://localhost:$port/authz/resources/thor/kick/.*ball")
  ->status_is(200)
  ->json_is('', ["/baseball","/football","/soccerball"]);

$t->get_ok("http://localhost:$port/authz/resources/tHOr/kick/.*ball")
  ->status_is(200)
  ->json_is('', ["/baseball","/football","/soccerball"]);

$t->get_ok('/actions')
  ->status_is(200)
  ->json_is('', [sort qw/create search miss view kick GET hit glob/]);

$t->get_ok('/groups/thor')->status_is(200)->json_is('', [qw/public superuser thor/]);

$t->get_ok('/groups/tHOr')->status_is(200)->json_is('', [qw/public superuser thor/]);

$t->get_ok('/groups/linus')->status_is(200)->json_is('', [qw/linus peanuts public/]);

$t->get_ok('/groups/nobody')->status_is(404);

1;


