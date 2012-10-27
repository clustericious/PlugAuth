package PlugAuth;

# ABSTRACT: Pluggable authentication and authorization server.
# VERSION

=head1 SYNOPSIS

In your /etc/PlugAuth.conf

 ---
 url: http://localhost:1234
 user_file: /etc/plugauth/user.txt
 group_file: /etc/plugauth/group.txt
 resource_file: /etc/plugauth/resource.txt
 host_file: /etc/plugauth/host.txt

Then create some users and groups

 % touch /etc/plugauth/user.txt \
         /etc/plugauth/group.txt \
         /etc/plugauth/resource.txt \
         /etc/plugauth/host.txt
 % plugauth start
 % plugauthclient create_user --user bob --password secret
 % plugauthclient create_user --user alice --password secret
 % plugauthclient create_group --group both --users bob,alice

L<PlugAuth::Client> for details.

In the configuration file for the Clustericious app
that will authenticate against PlugAuth:

 ---
 plug_auth:
   url: http://localhost:1234

L<Clustericious::Plugin::PlugAuth> for details.

=head1 DESCRIPTION

The PlugAuth server provides an HTTP API
for authentication and authorization.  The
authentication API is HTTP Basic Authentication.
The authorization API is based on users,
groups, resources, and hosts.

Credentials are verified against either flat
files or an ldap server.  Authorization is
done using flat files.

Here is how PlugAuth can be used with
a REST service.

  client
    |
    | HTTP
    |
 /-----------\          /------------\
 |   REST    |   HTTP   |            | --> files
 |  service  |  ------> |  PlugAuth  |
 |           |          |            | --> ldap
 \-----------/          \------------/

=over 4

=item 1.

Client (web browser or other) sends an  HTTP reqeust to the service.

=item 2

The service sends an HTTP basic auth
request to PlugAuth with the user's
credentials

=item 3

PlugAuth performs authentication (see AUTHENTICATION
below) and returns the appropriate HTTP status code.

=item 4

The REST service sends the HTTP status code to
the client if authentication has failed.

=item 5

The REST service may optionally check the client's
host, and if it is "trusted", authorization succeeds.

=item 6

If not, the REST service sends an authorization
request to PlugAuth, asking whether the client
has permission to perform an "action" on a "resource".
Both the action and resource are arbitrary strings, though
one reasonable default is sending the HTTP method as
the action, and the URL path as the resource.  (see
AUTHORIZATION below).

=item 7

PlugAuth returns a response code to the REST service
indicating whether or not authorization should succeed.

=item 8

The REST service returns the appropriate response to the
client.

=back

If the REST service uses Apache, see L<SimpleAuthHandler> for
Apache authorization/authentication handlers.

If the REST service is written in Perl, see L<SimpleAuth::Client>.

If the REST service uses Clustericious, see L<Clustericious::Plugin::SimpleAuth>.

=head2 AUTHENTICATION

Authentication is performed using either a flat files in the same
format as an apache htpasswd file or with an LDAP server.  The
configuration file indicates the location of the file or ldap
server.  See CONFIGURATION below.

=head2 AUTHORIZATION

Checking the authorization is done by sending GET requests to
urls of the form

 /authz/user/#user/#action/(*resource)

where I<#user> and I<#action> are strings (no slashes),
and I<*resource> is a string which may have slashes.
A response code of 200 indicates that access should
be granted, 403 indicates that the resource is forbidden.
A user is granted access to a resource if one of
of the following conditions are met :

=over 4

=item

the user is specifically granted access to that
resource, i.e. a line of the form

 /resource (action) username

appears in the resources file (see CONFIGURATION).

=item

the user is a member of a group which is granted
access to that resource.

=item

the user or a group containing the user is granted
access to a resource which is a prefix of the requested
resource.  i.e.

 / (action) username

would grant access to "username" to perform "action" on
any resource.

=item

Additionally, given a user, an action, and a regular expression,
it is possible to find _all_ of the resources matching that
regular expression for which the user has access.  This
can be done by sending a GET request to

 /authz/resources/(.user)/(.action)/(*regex)

=item

Host-based authorization is also possible -- sending a get
request to

    /host/(.host)/trusted

where ".host" is a string representing a hostname, returns
200 if the host-based authorization should succeed, and
403 otherwise.

=back

=head2 CONFIGURATION

Server configuration is done in $HOME/etc/PlugAuth.conf
which is a Clustericious::Config style file.  Here is an
example :

 ---
 url           : http://localhost:1234
 user_file     : /etc/pluginauth/user.txt
 group_file    : /etc/plugauth/group.txt
 resource_file : /etc/plugauth/resource.txt
 host_file     : /etc/plugauth/host.txt

It possible to have multiple user files with yaml list, e.g.

 user_file :
   - /etc/plugauth/user.txt
   - /etc/plugauth/more_users.txt

It is also possible to use LDAP for authentication, like so :

 ldap :
   server : 198.118.255.141:389
   path : /ou=people,dc=users,dc=eosdis,dc=nasa,dc=gov

The above will allow PlugAuth to be started via "plugauth daemon"
using the built-in webserver.  To use other webservers, additional
configuration is required.  For instance, after adding this to the
configuration file :

 start_mode: hypnotoad
 hypnotoad :
   listen : 'http://localhost:8099'
   env :
     %# Automatically generated configuration file
     HYPNOTOAD_CONFIG : /var/run/pluginauth/pluginauth.hypnotoad.conf

The command "pluginauth start" will start a hypnotoad webserver.
See Clustericious::Config for more examples, including use with nginx,
lighttpd, Plack or Apache.

PlugAuth will
detect when files have been changed on the next request so you do not
need to restart PlugAuth.

user.txt looks like apache's htpasswd files, and entries can be changed
either by using htpasswd or L<SimpleAuth::Client>.

 alice:AR2NVnqrzOh2M
 bob:fucVibC2NzOtg

group.txt looks like /etc/group.  Entries can be changed either by
using your favorite text editor, or by using L<SimpleAuth::Client>.
For each user there is also a group which contains just that user.
In this example there are groups alice and bob which contain just the
user alice and bob respectively.

 both : alice, bob

Group members can also be specified using a glob which matches
against the set of users:

 all : *

(see Text::Glob for details about globs)

Each line of resource.txt has a resource, an action (in parentheses),
and then a list of users or groups.  The line grants permission for
those groups to perform that action on that resource :

 /house/door (enter) : alice, bob
 /house/backdoor (enter) : both
 /house/window (break) : alice
 /house (GET) : bob

The host file /etc/pluginauth/host.txt looks like this :

 192.168.1.99:trusted
 192.168.1.100:trusted

The IP addresses on the right represent hosts from which
authorization should succeed.

=head1 TODO

Test the LDAP support.

Apply authorization to the pluginauth server itself: currently anyone
can query about anyone else's authorization.

=head1 SEE ALSO

L<Clustericious::Plugin::SimpleAuth>,
L<SimpleAuth::Client>

=cut

use strict;
use warnings;
use v5.10;
use base 'Clustericious::App';
use PlugAuth::Routes;
use Log::Log4perl qw( :easy );
use Role::Tiny ();
use List::MoreUtils qw( all );
use PlugAuth::Role::Plugin;

sub startup {
    my $self = shift;
    $self->SUPER::startup(@_);
    $self->plugin('Subdispatch');

    PlugAuth::Role::Plugin->global_config($self->config);

    my @plugins_config = eval {
        my $plugins = $self->config->plugins(default => []);
        ref($plugins) ? @$plugins : ($plugins);
    };

    my $auth_plugin;
    my $authz_plugin;
    my $admin_plugin;
    my @refresh_plugins;
    
    foreach my $plugin_class (reverse @plugins_config)
    {
        eval qq{ require $plugin_class };
        LOGDIE $@ if $@;
        Role::Tiny::does_role($plugin_class, 'PlugAuth::Role::Plugin')
            || LOGDIE "$plugin_class is not a PlugAuth plugin";
        
        my $plugin;
        if($plugin_class->does('PlugAuth::Role::Instance'))
        {
            $plugin = $plugin_class->new($self->config);
        }
        else
        {
            $plugin = $plugin_class;
        }

        $auth_plugin = $plugin if $plugin->does('PlugAuth::Role::Auth');
        $authz_plugin = $plugin if $plugin->does('PlugAuth::Role::Authz');
        $admin_plugin = $plugin if $plugin->does('PlugAuth::Role::Admin');
        push @refresh_plugins, $plugin if $plugin->does('PlugAuth::Role::Refresh')
    }

    unless(all { defined $_ } ($auth_plugin,$authz_plugin,$admin_plugin))
    {
        my $plugin;
        if($self->config->ldap(default => '')) {
            require PlugAuth::Plugin::LDAP;
            $plugin = 'PlugAuth::Plugin::LDAP';
        } else {
            require PlugAuth::Plugin::FlatFiles;
            $plugin = 'PlugAuth::Plugin::FlatFiles';
        }
        push @refresh_plugins, $plugin;
        $auth_plugin  //= $plugin;
        $authz_plugin //= $plugin;
        $admin_plugin //= $authz_plugin eq 'PlugAuth::Plugin::FlatFiles' ? $authz_plugin : do {
          require PlugAuth::Plugin::Unimplemented;
          'PlugAuth::Plugin::Unimplemented';
        };
    }

    $self->helper(data    => sub { $auth_plugin                        });
    $self->helper(auth    => sub { $auth_plugin                        });
    $self->helper(authz   => sub { $authz_plugin                       });
    $self->helper(admin   => sub { $admin_plugin                       });
    $self->helper(refresh => sub { $_->refresh for @refresh_plugins; 1 });
}

# Silence warnings; this is only used for for session
# cookies, which we don't use.
__PACKAGE__->secret(rand);

1;

