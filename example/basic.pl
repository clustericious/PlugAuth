package PlugAuthExample;

use base qw( Clustericious::App );

package PlugAuthExample::Routes;

use Clustericious::RouteBuilder;

authenticate;
authorize;

get '/' => sub { shift->render_text('hello') };

package main;

PlugAuthExample->new->start;
