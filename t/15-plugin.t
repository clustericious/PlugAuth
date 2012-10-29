use strict;
use warnings;
use File::HomeDir::Test;
use File::HomeDir;
use File::Spec;
use Test::More tests => 27;
use PlugAuth;
use Clustericious::Config;
use YAML ();
use Test::Differences;

my $config_filename = File::Spec->catfile(File::HomeDir->my_home, qw( etc PlugAuth.conf ));
mkdir(File::Spec->catdir(File::HomeDir->my_home, 'etc'));

do {
  YAML::DumpFile($config_filename, {});
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is ref($app->data), 'PlugAuth::Plugin::FlatAuth', 'data = FlatAuth by default';
};

eval q{
  package
    PlugAuth::Plugin::LDAP;
  use Role::Tiny::With;
  with 'PlugAuth::Role::Plugin';
  with 'PlugAuth::Role::Auth';
  sub check_credentials {}
  $INC{'PlugAuth/Plugin/LDAP.pm'} = __FILE__;
};
die $@ if $@;

do {
  YAML::DumpFile($config_filename, { ldap => { } });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is ref($app->data), 'PlugAuth::Plugin::LDAP', 'data = LDAP when LDAP is mentioned.';
};

do {
  eval q{
    package 
      FOoO;
    use Role::Tiny::With;
    with 'PlugAuth::Role::Plugin';
    sub new { bless { }, __PACKAGE__ }
    $INC{'FOoO.pm'} = __FILE__;
  };
  die $@ if $@;
  
  ok eval { Role::Tiny::does_role('FOoO', 'PlugAuth::Role::Plugin') }, "class method does";
  diag $@ if $@;
  
  my $foo = eval { FOoO->new };
  diag $@ if $@;
  isa_ok $foo, 'FOoO';
  
  ok eval { $foo->does('PlugAuth::Role::Plugin') }, 'instance method does';
  diag $@ if $@;
  
};

eval q{
  package
    JustAuth;
  use Role::Tiny::With;
  with 'PlugAuth::Role::Plugin';
  with 'PlugAuth::Role::Auth';
  $INC{'JustAuth.pm'} = __FILE__;
  sub check_credentials {}
};
die $@ if $@;

do {
  YAML::DumpFile($config_filename, { plugins => [ 'JustAuth' ] });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is ref $app->data,  'JustAuth',                    '[JustAuth@] data  = JustAuth';
  is ref $app->auth,  'JustAuth',                    '[JustAuth@] auth  = JustAuth';
  is ref $app->authz, 'PlugAuth::Plugin::FlatAuthz', '[JustAuth@] authz = FlatAuthz';
};

do {
  YAML::DumpFile($config_filename, { plugins => 'JustAuth' });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is ref $app->data,  'JustAuth',                    '[JustAuth$] data  = JustAuth';
  is ref $app->auth,  'JustAuth',                    '[JustAuth$] auth  = JustAuth';
  is ref $app->authz, 'PlugAuth::Plugin::FlatAuthz', '[JustAuth$] authz = FlatAuthz';
};
  
eval q{
  package
    JustAuthz;
  use Role::Tiny::With;
  with 'PlugAuth::Role::Plugin';
  with 'PlugAuth::Role::Authz';
  $INC{'JustAuthz.pm'} = __FILE__;
  sub can_user_action_resource {} 
  sub match_resources {} 
  sub host_has_tag {} 
  sub actions {} 
  sub groups_for_user {} 
  sub all_groups {} 
  sub users_in_group {}
};
die $@ if $@;

do {
  YAML::DumpFile($config_filename, { plugins => [ 'JustAuthz' ] });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is ref $app->data,  'PlugAuth::Plugin::FlatAuth',      '[JustAuthz@] data  = FlatAuth';
  is ref $app->auth,  'PlugAuth::Plugin::FlatAuth',      '[JustAuthz@] auth  = FlatAuth';
  is ref $app->authz, 'JustAuthz',                       '[JustAuthz@] authz = JustAuthz';
};

eval q{
  package
    JustRefresh;
  use Role::Tiny::With;
  with 'PlugAuth::Role::Plugin';
  with 'PlugAuth::Role::Refresh';
  my $refresh_count = 0;
  sub refresh { $refresh_count ++ }
  sub get_refresh_count { $refresh_count }
  $INC{'JustRefresh.pm'} = __FILE__;  
};
die $@ if $@;

ok(JustRefresh->does('PlugAuth::Role::Plugin'), "JustRefresh does Plugin");
ok(JustRefresh->does('PlugAuth::Role::Refresh'), "JustRefresh does Refresh");

do {
  is(JustRefresh->get_refresh_count, 0, "refresh count = 0");
  YAML::DumpFile($config_filename, { plugins => [ qw( JustRefresh JustAuth JustAuthz ) ] });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is(JustRefresh->get_refresh_count, 0, "refresh count = 0");
  eval { $app->refresh };
  diag $@ if $@;
  is(JustRefresh->get_refresh_count, 1, "refresh count = 1");
};


eval q{
  package
    List1;
  use Role::Tiny::With;
  with 'PlugAuth::Role::Plugin';
  with 'PlugAuth::Role::Auth';
  sub check_credentials { 0 }
  sub all_users { qw( foo bar ) }
  $INC{'List1.pm'} = __FILE__;
};
die $@ if $@;

eval q{
  package
    List2;
  use Role::Tiny::With;
  with 'PlugAuth::Role::Plugin';
  with 'PlugAuth::Role::Auth';
  sub check_credentials { 0 }
  sub all_users { qw( baz ) }
  $INC{'List2.pm'} = __FILE__;
};
die $@ if $@;

do {
  YAML::DumpFile($config_filename, { plugins => [ 'List1', 'List2' ] });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  eq_or_diff [sort $app->auth->all_users], [sort qw( foo bar baz )], "all_users = foo bar baz";
};