use strict;
use warnings;
use Test::More tests => 11;

use_ok 'PlugAuth';
use_ok 'PlugAuth::Routes';
use_ok 'PlugAuth::Plugin::FlatFiles';
use_ok 'PlugAuth::Plugin::LDAP';
use_ok 'PlugAuth::Plugin::Unimplemented';

use_ok 'PlugAuth::Role::Admin';
use_ok 'PlugAuth::Role::Auth';
use_ok 'PlugAuth::Role::Authz';
use_ok 'PlugAuth::Role::Instance';
use_ok 'PlugAuth::Role::Plugin';
use_ok 'PlugAuth::Role::Refresh';
