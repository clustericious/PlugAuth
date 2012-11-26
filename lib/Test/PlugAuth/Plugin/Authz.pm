package Test::PlugAuth::Plugin::Authz;

use strict;
use warnings;
use v5.10;
use Test::Builder;
use Role::Tiny ();
use PlugAuth;
use File::Temp qw( tempdir );
use YAML qw( DumpFile );
use base qw( Exporter );

our @EXPORT = qw( run_tests );

# FIXME: finish this test

# ABSTRACT: Test a PlugAuth Authz plugin for correctness
# VERSION

=head1 SYNOPSIS

 use Test::PlugAuth::Plugin::Authz;
 run_tests 'MyPlugin';  # runs tests against PlugAuth::Plugin::MyPlugin

=head1 FUNCTIONS

=head2 run_tests $plugin_name, [ $global_config, [ $plugin_config ] ]

Run the specification tests against the given plugin.  The configuraton
arguments are optional.  The first is the hash which is usually found in
~/etc/PlugAuth.conf and the second is the plugin config.

=cut

my $Test = Test::Builder->new;

sub run_tests
{
  my($class, $global_config, $plugin_config) = @_;
  $class = "PlugAuth::Plugin::$class" unless $class =~ /::/;
  eval qq{ use $class };
  die $@ if $@;
  
  $Test->plan( tests => 26 );
  
  $global_config //= {};
  
  local $ENV{CLUSTERICIOUS_CONF_DIR} = do {
    my $dir = tempdir(CLEANUP => 1);
    my $list_fn = File::Spec->catfile($dir, 'user_list.txt');
    do {
      use autodie;
      open my $fh, '>', $list_fn;
      say $fh "optimus";
      say $fh "primus";
      say $fh "megatron";
      say $fh "grimlock";
      close $fh;
    };
    
    DumpFile(File::Spec->catfile($dir, 'PlugAuth.conf'), {
      %$global_config,
      plugins => [
        {
          'PlugAuth::Plugin::FlatUserList' => {
          user_list_file => $list_fn,
          },
        }
      ],
    });
    $dir;
  };
  
  $global_config = Clustericious::Config->new($global_config)
    unless eval { $global_config->isa('Clustericious::Config') };
  $plugin_config //= {};
  
  my $object = eval { $class->new($global_config, $plugin_config, PlugAuth->new()) };
  my $error = $@;
  if(ref $object)
  {
    $Test->ok(1, "New returns a reference");
  }
  else
  {
    $Test->ok(0, "New returns a reference");
    $Test->diag("ERROR: $error");
  }
  
  $Test->ok( Role::Tiny::does_role($object, 'PlugAuth::Role::Plugin'),  'does Plugin');
  $Test->ok( Role::Tiny::does_role($object, 'PlugAuth::Role::Authz'), 'does Auth');
  
  my $refresh = Role::Tiny::does_role($object, 'PlugAuth::Role::Refresh') ? sub { $object->refresh } : sub {};
  $refresh->();
  
  foreach my $username (qw( optimus primus megatron grimlock ))
  {
    my $groups = $object->groups_for_user($username);
    my $pass = ref($groups) eq 'ARRAY' && $#$groups == 0 && $groups->[0] eq $username;
    $Test->ok( $pass, "user $username belongs to exactly one group: $username" );
  }
  
  do {
    do {
      my @groups = $object->all_groups;
      $Test->ok( $#groups == -1, "no groups" );
    };
    
    $Test->ok( eval { $object->create_group( 'group1', 'optimus,primus' ) } == 1, "create_group returned 1" );
    $Test->diag($@) if $@;
    $refresh->();
    
    do {
      my @groups = $object->all_groups;
      $Test->ok( $#groups == 0 && $groups[0] eq 'group1', 'group1 exists' );
    
      my @optimus  = sort @{ $object->groups_for_user('optimus') };
      my @primus   = sort @{ $object->groups_for_user('primus') };
      my @megatron = sort @{ $object->groups_for_user('megatron') };
    
      $Test->ok( $#optimus == 1 && $optimus[0] eq 'group1' && $optimus[1] eq 'optimus',
                 "optimus groups = optimus,group1");
      $Test->ok( $#primus == 1 && $primus[0] eq 'group1' && $primus[1] eq 'primus',
                 "primus groups = primus,group1");
      $Test->ok( $#megatron == 0 && $megatron[0] eq 'megatron',
                 "megatron groups = megatron" );
    
      my @users = sort @{ $object->users_in_group('group1') };
      my $pass = $#users == 1 && $users[0] eq 'optimus' && $users[1] eq 'primus';
      $Test->ok( $pass, "group1 = optimus, primus" );
      $Test->diag("group1 actually = [ ", join(', ', @users) , " ]")
        unless $pass;
    };
    
    $Test->ok( eval { $object->update_group('group1', "optimus,megatron") } == 1, "update_group returned 1" );
    $Test->diag($@) if $@;
    $refresh->();

    do {
      my @groups = $object->all_groups;
      $Test->ok( $#groups == 0 && $groups[0] eq 'group1', 'group1 exists' );
    
      my @optimus  = sort @{ $object->groups_for_user('optimus') };
      my @primus   = sort @{ $object->groups_for_user('primus') };
      my @megatron = sort @{ $object->groups_for_user('megatron') };
    
      $Test->ok( $#optimus == 1 && $optimus[0] eq 'group1' && $optimus[1] eq 'optimus',
                 "optimus groups = optimus,group1");
      $Test->ok( $#primus == 0 && $primus[0] eq 'primus',
                 "primus groups = primus");
      $Test->ok( $#megatron == 1 && $megatron[0] eq 'group1' && $megatron[1] eq 'megatron',
                 "megatron groups = group1,megatron" );
    
      my @users = sort @{ $object->users_in_group('group1') };
      my $pass = $#users == 1 && $users[0] eq 'megatron' && $users[1] eq 'optimus';
      $Test->ok( $pass, "group1 = megatron, optimus" );
      $Test->diag("group1 actually = [ ", join(', ', @users) , " ]")
        unless $pass;
    };
    
    $Test->ok( eval { $object->delete_group('group1') } == 1, "delete_group returned 1" );
    $Test->diag($@) if $@;
    $refresh->();
    
    do {
      my @groups = $object->all_groups;
      $Test->ok( $#groups == -1, 'group1 DOES NOT exists' );
    
      my @optimus  = sort @{ $object->groups_for_user('optimus') };
      my @primus   = sort @{ $object->groups_for_user('primus') };
      my @megatron = sort @{ $object->groups_for_user('megatron') };
    
      $Test->ok( $#optimus == 0 && $optimus[0] eq 'optimus',
                 "optimus groups = group1");
      $Test->ok( $#primus == 0 && $primus[0] eq 'primus',
                 "primus groups = primus");
      $Test->ok( $#megatron == 0 && $megatron[0] eq 'megatron',
                 "megatron groups = megatron" );
    
      my $users = $object->users_in_group('group1');
      my $pass = ! defined $users;
      $Test->ok( $pass, "group1 is empty" );
    };
  };
  
  # TODO: can_user_action_resource
  # TODO: match_resources
  # TODO: host_has_tag
  # TODO: actions
  # TODO: grant
  # TODO: revoke
}

1;

=head1 SEE ALSO

L<PlugAuth>,
L<PlugAuth::Guide::Plugin>

=cut
