use strict;
use warnings;
use Test::More tests => 3;
use PlugAuth::SelfAuth;
use Test::Differences;

my $plugins = eval { PlugAuth::SelfAuth->new };
diag $@ if $@;
isa_ok $plugins, 'PlugAuth::SelfAuth';

eq_or_diff $plugins->namespaces, [
   'Mojolicious::Plugin',
   'PlugAuth::SelfAuth',
   'Clustericious::Plugin'], 'namespaces = PlugAuth::SelfAuth, Mojolicious::Plugin, Clustericious::Plugin';

$plugins->namespaces(['Mojolicious::Plugin','Clustericious::Plugin']);

eq_or_diff $plugins->namespaces, [
   'Mojolicious::Plugin',
   'PlugAuth::SelfAuth',
   'Clustericious::Plugin'], 'namespaces = PlugAuth::SelfAuth, Mojolicious::Plugin, Clustericious::Plugin';

