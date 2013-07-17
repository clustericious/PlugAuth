use strict;
use warnings;
BEGIN {   eval 'use Test::Clustericious::Log' }
use Test::More tests => 1;
use PlugAuth;
use Test::Differences;

my $plug_auth = PlugAuth->new;
isa_ok $plug_auth->plugin('plug_auth'), 'Clustericious::Plugin::SelfPlugAuth';
