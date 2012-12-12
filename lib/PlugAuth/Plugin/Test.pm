package PlugAuth::Plugin::Test;

# ABSTRACT: Test Plugin server
# VERSION

use strict;
use warnings;
use PlugAuth::Plugin::FlatAuth;
use PlugAuth::Plugin::FlatAuthz;
use Role::Tiny::With;

with 'PlugAuth::Role::Plugin';
with 'PlugAuth::Role::Refresh';
with 'PlugAuth::Role::Auth';
with 'PlugAuth::Role::Authz';

sub init
{
  my($self) = @_;
}

sub refresh
{
  my($self) = @_;
  $self->real_auth->refresh;
  $self->real_authz->refresh;
  1;
}

sub check_credentials        { shift->real_auth->check_credentials(@_) }
sub create_user              { shift->real_auth->create_user(@_) }
sub change_password          { shift->real_auth->change_password(@_) }
sub delete_user              { shift->real_auth->delete_user(@_) }
sub all_users                { shift->real_auth->all_users }
sub can_user_action_resource { shift->real_authz->can_user_action_resource(@_) }

sub match_resources { shift->real_authz->match_resources(@_) }
sub host_has_tag    { shift->real_authz->host_has_tag(@_) }
sub actions         { shift->real_authz->actions(@_) }
sub groups_for_user { shift->real_authz->groups_for_user(@_) }
sub all_groups      { shift->real_authz->all_groups(@_) }
sub users_in_group  { shift->real_authz->users_in_group(@_) }

sub create_group { shift->real_authz->create_group(@_) }
sub delete_group { shift->real_authz->delete_group(@_) }
sub grant        { shift->real_authz->grant(@_) }
sub revoke       { shift->real_authz->revoke(@_) }
sub granted      { shift->real_authz->granted(@_) }
sub update_group { shift->real_authz->update_group(@_) }

sub real_auth
{
  my($self) = @_;
  
  unless(defined $self->{real_auth})
  {
    my $auth = $self->{real_auth} = new PlugAuth::Plugin::FlatAuth(
      Clustericious::Config->new({}),
      Clustericious::Config->new({}),
      $self->app
    );
    $auth->create_user('primus', 'spark');
    $auth->create_user('optimus', 'matrix');
    $auth->refresh;
  }
  
  return $self->{real_auth};
}

sub real_authz
{
  my($self) = @_;
  
  unless(defined $self->{real_authz})
  {
    my $auth = $self->real_auth;
    my $authz = $self->{real_authz} = new PlugAuth::Plugin::FlatAuthz(
      Clustericious::Config->new({}),
      Clustericious::Config->new({}),
      $self->app
    );
    $authz->create_group('admin', 'primus');
    $authz->refresh;
    $authz->grant('admin', 'accounts', '/');
    $authz->grant('primus', 'accounts', '/');
  }
  
  return $self->{real_authz};
}

1;
