package ExampleAppExample;

use base qw( Clustericious::App );

package ExampleAppExample::Routes;

use Clustericious::RouteBuilder;

get '/' => sub { shift->render_text('hello') };

authenticate;
authorize;

get '/some/user/resource' => sub { shift->render_text('hello') };

package main;

ExampleAppExample->new->start;
