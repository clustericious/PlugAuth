use strict;
use warnings;
use File::HomeDir::Test;
use File::HomeDir;
use File::Spec;
use Test::More tests => 32;
use PlugAuth;
use Clustericious::Config;
use YAML ();

my $config_filename = File::Spec->catfile(File::HomeDir->my_home, qw( etc PlugAuth.conf ));
mkdir(File::Spec->catdir(File::HomeDir->my_home, 'etc'));

do {
  YAML::DumpFile($config_filename, {});
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is $app->data, 'PlugAuth::Plugin::FlatFiles', 'data = FlatFiles by default';
};

do {
  YAML::DumpFile($config_filename, { ldap => { } });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is $app->data, 'PlugAuth::Plugin::LDAP', 'data = LDAP when LDAP is mentioned.';
};

do {
  eval {
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
  sub all_users {}
};
die $@ if $@;

do {
  YAML::DumpFile($config_filename, { plugins => [ 'JustAuth' ] });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is $app->data,  'JustAuth',                    '[JustAuth@] data  = JustAuth';
  is $app->auth,  'JustAuth',                    '[JustAuth@] auth  = JustAuth';
  is $app->authz, 'PlugAuth::Plugin::FlatFiles', '[JustAuth@] authz = FlatFiles';
  is $app->admin, 'PlugAuth::Plugin::FlatFiles', '[JustAuth@] admin = FlatFiles';
};

do {
  YAML::DumpFile($config_filename, { plugins => 'JustAuth' });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is $app->data,  'JustAuth',                    '[JustAuth$] data  = JustAuth';
  is $app->auth,  'JustAuth',                    '[JustAuth$] auth  = JustAuth';
  is $app->authz, 'PlugAuth::Plugin::FlatFiles', '[JustAuth$] authz = FlatFiles';
  is $app->admin, 'PlugAuth::Plugin::FlatFiles', '[JustAuth$] admin = FlatFiles';
};
  
eval q{
  package
    JustAuth;
  with 'PlugAuth::Role::Instance';
  sub new { bless {}, __PACKAGE__ };
};
diag $@ if $@;

do {
  YAML::DumpFile($config_filename, { plugins => 'JustAuth' });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is ref($app->data),  'JustAuth',                    '[JustAuth-] data  = JustAuth';
  is ref($app->auth),  'JustAuth',                    '[JustAuth-] auth  = JustAuth';
  is     $app->authz,  'PlugAuth::Plugin::FlatFiles', '[JustAuth-] authz = FlatFiles';
  is     $app->admin,  'PlugAuth::Plugin::FlatFiles', '[JustAuth-] admin = FlatFiles';
};

eval {
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
  sub groups {} 
  sub all_groups {} 
  sub users {}
};
die $@ if $@;

do {
  YAML::DumpFile($config_filename, { plugins => [ 'JustAuthz' ] });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is $app->data,  'PlugAuth::Plugin::FlatFiles',     '[JustAuthz@] data  = FlatFiles';
  is $app->auth,  'PlugAuth::Plugin::FlatFiles',     '[JustAuthz@] auth  = FlatFiles';
  is $app->authz, 'JustAuthz',                       '[JustAuthz@] authz = JustAuthz';
  is $app->admin, 'PlugAuth::Plugin::Unimplemented', '[JustAuthz@] admin = Unimplemented';
};

eval {
  package
    JustAdmin;
  use Role::Tiny::With;
  with 'PlugAuth::Role::Plugin';
  with 'PlugAuth::Role::Admin';
  $INC{'JustAdmin.pm'} = __FILE__;
  sub create_user {} 
  sub change_password {} 
  sub delete_user {} 
  sub create_group {} 
  sub delete_group {} 
  sub grant {}
};
die $@ if $@;

do {
  YAML::DumpFile($config_filename, { plugins => [ 'JustAdmin' ] });
  my $app = PlugAuth->new;
  isa_ok $app, 'PlugAuth';
  $app->startup;
  is $app->data,  'PlugAuth::Plugin::FlatFiles',     '[JustAdmin@] data  = FlatFiles';
  is $app->auth,  'PlugAuth::Plugin::FlatFiles',     '[JustAdmin@] auth  = FlatFiles';
  is $app->authz, 'PlugAuth::Plugin::FlatFiles',     '[JustAdmin@] authz = FLatFiles';
  is $app->admin, 'JustAdmin',                       '[JustAdmin@] admin = JustAdmin';
};
