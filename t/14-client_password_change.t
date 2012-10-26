use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More;
use Test::Mojo;
use PlugAuth;
use Test::Differences;

$ENV{LOG_LEVEL} = 'FATAL';

BEGIN {
  my $min_version = '0.09';
  plan skip_all => 'requires SimpleAuth::Client' 
    # fake it if the SimpleAuth::Client dist is checkout as a sibling
    unless eval q{
      use lib "$FindBin::Bin/../../SimpleAuth-Client/lib";
      use SimpleAuth::Client;
      1;
    }
    # test only works if SimpleAuth::Client is installed
    ||     eval qq{ use SimpleAuth::Client $min_version; 1 };
  plan tests => 4;
}

my $client = do {
  my $t = Test::Mojo->new('PlugAuth');
  my $port = $t->ua->app_url->port;
  my $client = SimpleAuth::Client->new(server_url => "http://localhost:$port");
  $client->client($t->ua);
  $client;
};

isa_ok $client, 'SimpleAuth::Client';

$client->login('optimus', 'matrix');
ok $client->auth, 'client.login(optimus, matrix); client.auth';

$client->login('primus', 'cybertron');
ok eval { $client->change_password('optimus', 'matrix1') }, 'client.change_password(optimus, matrix1)';
diag $@ if $@;

$client->login('optimus', 'matrix1');
ok $client->auth, 'client.login(optimus, matrix1); client.auth';
