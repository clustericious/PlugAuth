use strict;
use warnings;
use 5.010001;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More;
use Test::Mojo;
use PlugAuth;
use Test::Differences;

$ENV{LOG_LEVEL} = 'FATAL';

$PlugAuth::VERSION = '0.01';

BEGIN {
  my $min_version = '0.09';
  plan skip_all => 'requires PlugAuth::Client' 
    # fake it if the PlugAuth::Client dist is checkout as a sibling
    unless eval q{
      use lib "$FindBin::Bin/../../PlugAuth-Client/lib";
      use PlugAuth::Client;
      1;
    }
    # test only works if PlugAuth::Client is installed
    ||     eval qq{ use PlugAuth::Client $min_version; 1 };
  plan tests => 17;
}

my $client = do {
  my $t = Test::Mojo->new('PlugAuth');
  my $port = eval { $t->ua->server->url->port } // $t->ua->app_url->port;
  my $client = PlugAuth::Client->new(server_url => "http://localhost:$port");
  $client->client($t->ua);
  $client;
};

isa_ok $client, 'PlugAuth::Client';

# The basics
is $client->welcome, 'welcome to plug auth', 'client.welcome';
is $client->version->[0], '0.01', 'client.version';

# Good password
$client->login('optimus', 'matrix');
ok $client->auth,  'client.login(optimus, matrix); client.auth';

# Bad password
$client->login('bogus', 'bogus');
ok !$client->auth, 'client.login(bogus, bogus); client.auth';

# Good authorization
ok $client->authz('optimus', 'open', '/matrix'), 'client.authz(optimus, open, /matrix)';
ok $client->authz('optimus', 'open', 'matrix'), 'client.authz(optimus, open, matrix)';

# Bad authorization
ok !$client->authz('galvatron', 'open', '/matrix'), 'client.authz(galvatron, open, /matrix)';

is $client->host_tag('1.2.3.4', 'trusted'), 'ok', 'client.host_tag';
is $client->host_tag('1.1.1.1', 'trusted'), undef, 'client.host_tag';

eq_or_diff [sort @{ $client->groups('optimus') }], [sort qw( optimus transformer autobot)], 'client.groups(optimus)';
eq_or_diff [sort @{ $client->groups('starscream') }], [sort qw( starscream transformer decepticon)], 'client.groups(starscream)';

eq_or_diff [sort @{ $client->actions } ], [sort qw( open fly lead transform )], 'client.actions';
eq_or_diff [sort @{ $client->user }], [sort qw( optimus grimlock starscream galvatron )], 'client.user';
eq_or_diff [sort @{ $client->group }], [sort qw( transformer autobot decepticon )], 'client.group';

eq_or_diff [sort @{ $client->users('autobot') }], [sort qw( optimus grimlock )], 'client.users(autobot)';

my %table;
foreach my $action (@{ $client->actions })
{
  my $resources = $client->resources('galvatron', $action, '.*');
  $table{$action} = $resources if @$resources > 0;
}

SKIP: {

  skip 'requires PlugAuth::Client 0.10', 1 
    unless !defined $PlugAuth::Client::VERSION
    ||     $PlugAuth::Client::VERSION > 0.09;

  eq_or_diff 
    eval { $client->action_resources('galvatron') }//{}, 
    { fly => ['/sky'], lead => ['/troops'], 'transform' => ['/body'] },
    'client.action_resources';
  diag $@ if $@;

}
