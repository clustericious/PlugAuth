package PlugAuth::Role::Authz;

use strict;
use warnings;
use Role::Tiny;

# ABSTRACT: Role for PlugAuth authorization plugins
# VERSION

=head1

Use this role when writing PlugAuth plugins that manage
authorization (ie. determine what the user has authorization
to actually do).

=cut

requires qw( 
  can_user_action_resource
  match_resources
  host_has_tag
  actions
  groups
  all_groups
  users
);


1;
