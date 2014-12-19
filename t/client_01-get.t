use Test::More $ENV{PLUGAUTH_LIVE_TESTS} ? "no_plan" : (skip_all => "Set PLUGAUTH_LIVE_TESTS to use PlugAuth configuration ");
use PlugAuth::Client;
use Log::Log4perl;

use strict;

Log::Log4perl->easy_init(level => "WARN");

diag "Contacting PlugAuth server";

my $r = PlugAuth::Client->new;

ok $r, "made a client object";

my $welcome = $r->welcome;

like $welcome, qr/welcome to plug auth/i, "got welcome message";

1;

