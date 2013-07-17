use strict;
use warnings;
use Test::Clustericious::Config;
use Test::Clustericious::Cluster;
use Test::More tests => 12;

create_directory_ok 'data';

my $cluster = Test::Clustericious::Cluster->new;
$cluster->create_cluster_ok(qw( PlugAuth ));

my $url = $cluster->url;
my $t   = $cluster->t;

my $app = $cluster->apps->[0];

sub json($) {
    ( { 'Content-Type' => 'application/json' }, Mojo::JSON->new->encode(shift) );
}

$app->authz->create_group('disabled', '');
$app->refresh;
$t->post_ok("$url/user", json { user => 'roger', password => 'rabbit' })
  ->status_is(200);
$t->post_ok("$url/user", json { user => 'bugs', password => 'bunny' })
  ->status_is(200);

$t->delete_ok("$url/group/disabled/bugs")
  ->status_is(200);

$url->userinfo('bugs:bunny');
$t->get_ok("$url/auth")
  ->status_is(200);

$url->userinfo('roger:rabit');
$t->get_ok("$url/auth")
  ->status_is(403);

exit;
  
__DATA__

@@ etc/PlugAuth.conf
---
% use File::Touch;
url: <%= cluster->url %>
plugins:
  - PlugAuth::Plugin::DisableGroup:
      disable_on_create: 1
  - PlugAuth::Plugin::FlatAuth: {}

% foreach my $file (qw( user group resource )) {
% touch(join '/', home, 'data', $file);
<%= $file %>_file: <%= home %>/data/<%= $file %>
% }
