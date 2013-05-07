use strict;
use warnings;
use Test::More tests => 2;
use File::HomeDir::Test;
use PlugAuth;

my $app = PlugAuth->new;
isa_ok $app, 'PlugAuth';

my $auth_plugin = $app->plugin('plug_auth');
isa_ok $auth_plugin, 'Clustericious::Plugin::SelfPlugAuth';
