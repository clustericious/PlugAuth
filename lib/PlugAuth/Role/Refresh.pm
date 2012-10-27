package PlugAuth::Role::Refresh;

use strict;
use warnings;
use Role::Tiny;

# ABSTRACT: Role for PlugAuth reload plugins
# VERSION

=head1 DESCRIPTION

Use this role for PlugAuth plugins which need to be refreshed
on every call.

=cut

requires qw( refresh );

1;
