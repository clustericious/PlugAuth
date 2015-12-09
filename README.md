# PlugAuth [![Build Status](https://secure.travis-ci.org/clustericious/PlugAuth.png)](http://travis-ci.org/clustericious/PlugAuth)

Pluggable authentication and authorization server.

# SYNOPSIS

In the configuration file for the Clustericious app that will authenticate
against PlugAuth:

    ---
    plug_auth:
      url: http://localhost:1234

and _authenticate_ and _authorize_ in your Clustericious application's Routes.pm:

    authenticate;
    authorize;
    
    get '/resource' => sub {
      # resource that requires authentication
      # and authorization
    };

# DESCRIPTION

(For a quick start guide on how to setup a PlugAuth server, please see
[PlugAuth::Guide::Server](https://metacpan.org/pod/PlugAuth::Guide::Server))

PlugAuth is a pluggable authentication and authorization server with a consistent
RESTful API.  This allows clients to authenticate and query authorization from a
PlugAuth server without worrying or caring whether the actual authentication happens
against flat files, PAM, LDAP or passed on to another PlugAuth server.

The authentication API is HTTP Basic Authentication.  The authorization API is based
on users, groups, resources and hosts.

The implementation for these can be swapped in and out depending on the plugins that
you select in the configuration file.  The default plugins for authentication 
([PlugAuth::Plugin::FlatAuth](https://metacpan.org/pod/PlugAuth::Plugin::FlatAuth)) and authorization ([PlugAuth::Plugin::FlatAuthz](https://metacpan.org/pod/PlugAuth::Plugin::FlatAuthz)) are
implemented with ordinary flat files and advisory locks using flock.

The are other plugins for ldap ([PlugAuth::Plugin::LDAP](https://metacpan.org/pod/PlugAuth::Plugin::LDAP)), [DBI](https://metacpan.org/pod/DBI) 
([PlugAuth::Plugin::DBIAuth](https://metacpan.org/pod/PlugAuth::Plugin::DBIAuth)), or you can write your own ([PlugAuth::Guide::Plugin](https://metacpan.org/pod/PlugAuth::Guide::Plugin)).

Here is a diagram that illustrates the most common use case for PlugAuth being used 
by a RESTful service:

     client
       |
       | HTTP
       |
    +-----------+          +------------+     +--------------+
    |   REST    |   HTTP   |            | --> | Auth Plugin  |  --> files
    |  service  |  ------> |  PlugAuth  |     +--------------+  --> ldap
    |           |          |            | --> | Authz Plugin |  --> ...
    +-----------+          +------------+     +--------------+

1. Client (web browser or other) sends an  HTTP request to the service.
2. The service sends an HTTP basic authentication request to PlugAuth with the user's credentials
3. PlugAuth performs authentication (see ["AUTHENTICATION"](#authentication)) and returns the appropriate 
HTTP status code.
4. The REST service sends the HTTP status code to the client if authentication has failed.
5. The REST service may optionally check the client's host, and if it is "trusted", 
authorization succeeds (see ["AUTHORIZATION"](#authorization)).
6. If not, the REST service sends an authorization request to PlugAuth, asking whether 
the client has permission to perform an "action" on a "resource". Both the action and 
resource are arbitrary strings, though one reasonable default is sending the HTTP 
method as the action, and the URL path as the resource.  (see ["AUTHORIZATION"](#authorization) below).
7. PlugAuth returns a response code to the REST service indicating whether or not 
authorization should succeed.
8. The REST service returns the appropriate response to the client.

If the REST service is written in Perl, see [PlugAuth::Client](https://metacpan.org/pod/PlugAuth::Client).

If the REST service uses Clustericious, see [Clustericious::Plugin::PlugAuth](https://metacpan.org/pod/Clustericious::Plugin::PlugAuth).

PlugAuth was originally written for scientific data processing clusters based on 
[Clustericious](https://metacpan.org/pod/Clustericious) in which all the services are RESTful servers distributed over a number
of different physical hosts, though it may be applicable in other contexts.

## AUTHENTICATION

Checking for authentication is done by sending a GET request to URLs of the form

    /auth

With the username and password specified as HTTP Basic credentials.  The actual 
mechanism used to verify authentication will depend on the authentication plugin being 
used.  The default is [PlugAuth::Plugin::FlatAuth](https://metacpan.org/pod/PlugAuth::Plugin::FlatAuth).

## AUTHORIZATION

Checking the authorization is done by sending GET requests to URLs of the form

    /authz/user/user/action/resource

where _user_ and _action_ are strings (no slashes), and _resource_ is a string 
which may have slashes. A response code of 200 indicates that access should be 
granted, 403 indicates that the resource is forbidden.  A user is granted access to a 
resource if one of of the following conditions are met:

- the user is specifically granted access to that resource, i.e. a line of the form

        /resource (action): username

    appears in the resources file (see ["CONFIGURATION"](#configuration)).

- the user is a member of a group which is granted access to that resource.
- the user or a group containing the user is granted access to a resource which is a 
prefix of the requested resource.  i.e.

        / (action): username

    would grant access to "username" to perform "action" on any resource.

- Additionally, given a user, an action, and a regular expression, it is possible to find 
_all_ of the resources matching that regular expression for which the user has access.  This
can be done by sending a GET request to

        /authz/resources/user/action/regex

- Host-based authorization is also possible -- sending a get
request to

        /host/host/trusted

    where ".host" is a string representing a hostname, returns
    200 if the host-based authorization should succeed, and
    403 otherwise.

For a complete list of the available routes and what they return see [PlugAuth::Routes](https://metacpan.org/pod/PlugAuth::Routes).

## CONFIGURATION

Server configuration is done in ~/etc/PlugAuth.conf which is a 
Clustericious::Config style file.  The configuration depends on which plugins you 
choose, consult your plugin's documentation.  The default plugins are
[PlugAuth::Plugin::FlatAuth](https://metacpan.org/pod/PlugAuth::Plugin::FlatAuth), [PlugAuth::Plugin::FlatAuthz](https://metacpan.org/pod/PlugAuth::Plugin::FlatAuthz).

Once the authentication and authorization has been configured, PlugAuth
can be started (like any [Mojolicious](https://metacpan.org/pod/Mojolicious) or [Clustericious](https://metacpan.org/pod/Clustericious) application)
using the daemon command:

    % plugauth daemon

This will use the built-in web server.  To use another web server, additional
configuration is required.  For example, after adding this:

    start_mode: hypnotoad
    hypnotoad :
      listen : 'http://localhost:8099'
      env :
        %# Automatically generated configuration file
        HYPNOTOAD_CONFIG : /var/run/pluginauth/pluginauth.hypnotoad.conf

This start command can be used to start a hypnotoad web server.

    % plugauth start

See [Clustericious::Config](https://metacpan.org/pod/Clustericious::Config) for more examples, including using with nginx,
lighttpd, Plack or Apache.

# EVENTS

See [PlugAuth::Routes](https://metacpan.org/pod/PlugAuth::Routes)

# SEE ALSO

[Clustericious::Plugin::PlugAuth](https://metacpan.org/pod/Clustericious::Plugin::PlugAuth),
[PlugAuth::Client](https://metacpan.org/pod/PlugAuth::Client),
[PlugAuth::Guide::Client](https://metacpan.org/pod/PlugAuth::Guide::Client),
[PlugAuth::Guide::Plugin](https://metacpan.org/pod/PlugAuth::Guide::Plugin),
[PlugAuth::Guide::Server](https://metacpan.org/pod/PlugAuth::Guide::Server)

# AUTHOR

Graham Ollis &lt;gollis@sesda3.com>

# COPYRIGHT AND LICENSE

This software is copyright (c) 2012 by NASA GSFC.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
