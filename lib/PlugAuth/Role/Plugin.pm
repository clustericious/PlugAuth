package PlugAuth::Role::Plugin;

use strict;
use warnings;
use v5.10;
use Role::Tiny;
use Scalar::Util qw( refaddr );

# ABSTRACT: Role for PlugAuth plugins
# VERSION

=head1 DESCRIPTION

Use this role when writing PlugAuth plugins.

=head1 METHODS

=head2 PlugAuth::Role::Plugin-E<gt>global_config

=head2 $plugin-E<gt>global_config

Get the global PlugAuth configuration (an instance of
L<Clustericious::Config>).

This method may be called as either an instance
or class method.

=cut

sub global_config
{
  my($class, $new_value) = @_;
  state $config;
  $config = $new_value if defined $new_value;
  $config;
}

=head2 PlugAuth::Role::Plugin->plugin_config

=head2 $plugin-E<gt>plugin_config

Get the plugin specific configuration.  This
method may be called as either an instance or
class method.

=cut

my %plugin_configs;

sub plugin_config
{
  my($self, $new_value) = @_;
  if(ref($self))
  {
    $self->{plugin_config} = $new_value if defined $new_value;
    return $self->{plugin_config};
  }
  else
  {
    $plugin_configs{refaddr $self} = $new_value if defined $new_value;
    return $plugin_configs{refaddr $self};
  }
}

1;
