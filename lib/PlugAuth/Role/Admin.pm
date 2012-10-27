package PlugAuth::Role::Admin;

use strict;
use warnings;
use Role::Tiny;

# ABSTRACT: Role for PlugAuth administration plugins
# VERSION

=head1 DESCRIPTION

Use this role when writing PlugAuth plugins which modifies any
of the authentication or authorization settings inside the
server.

=cut

requires qw(
  create_user
  change_password
  delete_user
  create_group
  delete_group
  grant
);

1;
