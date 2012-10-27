package PlugAuth::Role::Auth;

use strict;
use warnings;
use Role::Tiny;

# ABSTRACT: Role for PlugAuth authentication plugins
# VERSION

=head1 DESCRIPTION

Use this role when writing PlugAuth plugins that manage 
authentication (ie. determine the identify of the user).

=cut

requires qw( 
  check_credentials
  all_users
);

1;
