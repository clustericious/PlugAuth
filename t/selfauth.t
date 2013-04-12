use strict;
use warnings;
use Test::More tests => 2;
use File::HomeDir::Test;
use PlugAuth;
use PlugAuth::SelfAuth;

my $app = PlugAuth->new;
isa_ok $app, 'PlugAuth';

$app->plugins(PlugAuth::SelfAuth->new);

my $auth_plugin = $app->plugin('plug_auth');
isa_ok $auth_plugin, 'PlugAuth::SelfAuth::PlugAuth';
