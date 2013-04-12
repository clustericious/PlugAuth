package PlugAuth::SelfAuth::PlugAuth;

use strict;
use warnings;
use Clustericious::Log;
use Mojo::ByteStream qw( b );
use Mojo::Base 'Mojolicious::Plugin';

# ABSTRACT: Self authentication for PlugAuth
# VERSION

=head1 DESCRIPTION

This class helps provide the self authentication/authorization mechanism
for PlugAuth.

=cut

sub register {
  my ($self, $app, $conf) = @_;
  PlugAuth::Role::Plugin->_self_auth_plugin($self);
  $self;
}

sub authenticate
{
  my($self, $c, $realm) = @_;

  TRACE ("Authenticating for realm $realm");
  # Everyone needs to send an authorization header
  my $auth = $c->req->headers->authorization or do {
    $c->res->headers->www_authenticate(qq[Basic realm="$realm"]);
    $c->render_text("auth required", layout => "", status => 401);
    return;
  };
  
  my ($method,$str) = split / /,$auth;
  my $userinfo = b($str)->b64_decode;
  my ($user,$pw) = split /:/, $userinfo;

  $c->refresh;
  if($c->authz->host_has_tag($c->tx->remote_address, 'trusted')
  || $c->auth->check_credentials($user,$pw)) {
    $c->stash(user => $user);
    return 1;
  }

  INFO "Authentication denied for $user";
  $c->res->headers->www_authenticate(qq[Basic realm="$realm"]);
  $c->render(text => "authentication failure", status => 401);
  return;
}

sub authorize
{
  my($self, $c, $action, $resource) = @_;
  my $user = $c->stash("user") or LOGDIE "missing user in authorize()";
  LOGDIE "missing action or resource in authorize()" unless @_==4;
  TRACE "Authorizing user $user, action $action, resource $resource";
  $resource =~ s[^/][/];
  my $found = $c->authz->can_user_action_resource($user, $action, $resource);
  if($found)
  {
    return 1;
  }
  else
  {
    $c->render(text => "unauthorized", status => 403);
    return 0;
  }
}

1;
