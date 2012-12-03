package PlugAuth::Routes;

# ABSTRACT: routes for plugauth
# VERSION

=head1 DESCRIPTION

This module defines the HTTP URL routes provided by L<PlugAuth>.
This document uses Mojolicious conventions to describe routes,
see L<Mojolicious::Guides::Routing> for details.

=cut

# There may be external authentication for these routes, i.e. using
# this CI to determine who can check/update other's access.

use strict;
use warnings;
use Log::Log4perl qw/:easy/;
use Mojo::ByteStream qw/b/;
use IO::File;
use List::MoreUtils qw/mesh/;
use Clustericious::RouteBuilder;
use Clustericious::Config;
use List::MoreUtils qw( uniq );

=head1 ROUTES

=head2 Public routes

These routes work for unauthenticated and unauthorized users.

=head3 GET /

Returns the string "welcome to plug auth"

=cut

get '/' => sub { shift->render_text("welcome to plug auth") } => "index" ;

ladder sub { shift->refresh };

=head3 GET /auth

=over 4

=item * if username and password provided using BASIC authentication and are correct

Return 200 ok

=item * if username and password provided using BASIC authentication but are not correct

Return 403 not ok

=item * if username and password are not provided using BASIC authentiation

Return 401 please authenticate

=back

=cut

# Check authentication for a user (http basic auth protocol).
get '/auth' => sub {
    my $self = shift;
    my $auth = $self->req->headers->authorization or do {
        $self->res->headers->www_authenticate('Basic "ACPS"');
        $self->res->code(401);
        $self->render(text => "please authenticate");
        return;
    };
    my ($method,$str) = split / /,$auth;
    my ($user,$pw) = split /:/, b($str)->b64_decode;

    my $ok = $self->auth->check_credentials($user,$pw);
    DEBUG "Authentication succeeded for user $user" if $ok;
    return $self->render_text("ok") if $ok;
    DEBUG "Authentication failed for user $user";
    $self->res->code(403);
    $self->render_text("not ok");
};

=head3 GET /authz/user/#user/#action/(*resource)

=over 4

=item * if the given user (#user) is permitted to perform the given action (#action) on the given resource (*resource)

Return 200 ok

=item * otherwise

Return 403 "unauthorized : $user cannot $action $resource"

=back

=cut

# Check authorization for a user to perform $action on $resource.
get '/authz/user/#user/#action/(*resource)' => sub {
    my $c = shift;
    # Ok iff the user is in a group for which $action on $resource is allowed.
    my ($user,$resource,$action) = map $c->stash($_), qw/user resource action/;
    $resource = "/$resource";
    TRACE "Checking authorization for $user to perform $action on $resource...";
    my $found = $c->authz->can_user_action_resource($user,$action,$resource);
    if ($found) {
        TRACE "Authorization succeeded ($found)";
        return $c->render(text => 'ok', status => 200);
    }
    TRACE "Authorization failed";
    $c->render(text => "unauthorized : $user cannot $action $resource", status => 403);
};

=head3 GET /authz/resources/#user/#action/(*resourceregex)

Returns a list of resources that the given user (#user) is permitted to perform
action (#action) on.  The regex is used to filter the results (*resourceregex).

=cut

# Given a user, an action and a regex, return a list of resources
# on which $user can do $action, where each resource matches that regex.
get '/authz/resources/#user/#action/(*resourceregex)' => sub  {
    my $c = shift;
    my ($user,$action,$resourceregex) = map $c->stash($_), qw/user action resourceregex/;
    TRACE "Checking $user, $action, $resourceregex";
    $resourceregex = qr[$resourceregex];
    my @resources;
    for my $resource ($c->authz->match_resources($resourceregex)) {
        TRACE "Checking resource $resource";
        push @resources, $resource if $c->authz->can_user_action_resource($user,$action,$resource);
    }
    $c->stash->{autodata} = [sort @resources];
};

=head3 GET /actions

Return a list of actions that PlugAuth knows about.

=cut

# Return a list of all defined actions
get '/actions' => sub {
    my($self) = @_;
    $self->stash->{autodata} = [ $self->authz->actions ];
};

=head3 GET /groups/#user

Return a list of groups that the given user (#user) belongs to. 

Returns 404 not ok if the user does not exist.

=cut

# All the groups for a user :
get '/groups/#user' => sub {
    my $c = shift;
    my $groups = $c->authz->groups_for_user($c->stash('user'));
    $c->render(text => 'not ok', status => 404) unless defined $groups;
    $c->stash->{autodata} = $groups;
};

=head3 GET /host/#host/:tag

=over 4

=item * if the given host (#host) has the given tag (:tag)

return 200 ok

=item * otherwise

return 403 not ok

=back

=cut

# Given a host and a tag (e.g. "trusted") return true if that host has
# that tag.
get '/host/#host/:tag' => sub {
    my $c = shift;
    my ($host,$tag) = map $c->stash($_), qw/host tag/;
    if ($c->authz->host_has_tag($host,$tag)) {
        TRACE "Host $host has tag $tag";
        return $c->render(text => "ok", status => 200);
    }
    TRACE "Host $host does not have tag $tag";
    return $c->render(text => "not ok", status => 403);
};

=head3 GET /user

Returns a list of all users that PlugAuth knows about.

=cut

get '/user' => sub {
    my $c = shift;
    $c->stash->{autodata} = [ uniq sort $c->auth->all_users ];
};

=head3 GET /group

Returns a list of all groups that PlugAuth knows about.

=cut

get '/group' => sub {
    my $c = shift;
    $c->stash->{autodata} = [ $c->authz->all_groups ];
};

=head3 GET /users/:group

Returns the list of users that belong to the given group (:group)

=cut

get '/users/:group' => sub {
    my $c = shift;
    my $users = $c->authz->users_in_group($c->stash('group'));
    $c->render(text => 'not ok', status => 404) unless defined $users;
    $c->stash->{autodata} = $users;
};

authenticate;
authorize 'accounts';

=head2 Accounts Routes

These routes are available to users authenticates and authorized to perform
the 'accounts' action.  They will return

=over 4

=item * 401

If no credentials are provided

=item * 403

If the user is unauthorized.

=item * 503

If the PlugAuth server cannot reach itself or the deligated PlugAuth server.

=back

=head3 POST /user

Create a user.  The C<username> and C<password> are provided autodata arguments
(JSON, YAML, form data, etc).

=cut

post '/user' => sub {
    my $c = shift;
    $c->refresh;
    $c->parse_autodata;
    my $user = $c->stash->{autodata}->{user};
    my $password = $c->stash->{autodata}->{password} || '';
    delete $c->stash->{autodata};
    if($c->auth->create_user($user, $password)) {
        $c->render(text => 'ok', status => 200);
        $c->app->emit('user_list_changed');
    } else {
        $c->render(text => "not ok", status => 403);
    }
};

=head3 DELETE /user/#user

Delete the given user (#user).  Returns 200 ok on success, 404 not ok on failure.

=cut

del '/user/#user' => sub {
    my $c = shift;
    $c->refresh;
    if($c->auth->delete_user($c->param('user'))) {
        $c->render(text => 'ok', status => 200);
        $c->app->emit('user_list_changed');
    } else {
        $c->render(text => 'not ok', status => 404);
    }
};

=head3 POST /group

Create a group.  The C<group> name and list of C<users> are provided as autodata
arguments (JSON, YAML, form data etc).  Returns 200 ok on success, 403 not ok
on failure.

=cut

post '/group' => sub {
    my $c = shift;
    $c->refresh;
    $c->parse_autodata;
    my $group = $c->stash->{autodata}->{group};
    my $users = $c->stash->{autodata}->{users};
    delete $c->stash->{autodata};
    $c->authz->create_group($group, $users)
    ? $c->render(text => 'ok', status => 200)
    : $c->render(text => "not ok", status => 403);
};

=head3 DELETE /group/:group

Delete the given group (:group).  Returns 200 ok on success, 403 not ok on failure.

=cut

del '/group/:group' => sub {
    my $c = shift;
    $c->refresh;
    $c->authz->delete_group($c->param('group') )
    ? $c->render(text => 'ok', status => 200)
    : $c->render(text => 'not ok', status => 404);
};

=head3 POST /group/:group

Update the list of users belonging to the given group (:group).  The list
of C<users> is provided as an autodata argument (JSON, YAML, form data etc.).
Returns 200 ok on success, 404 not ok on failure.

=cut

post '/group/:group' => sub {
    my $c = shift;
    $c->refresh;
    $c->parse_autodata;
    my $users = $c->stash->{autodata}->{users};
    delete $c->stash->{autodata};
    $c->authz->update_group($c->param('group'), $users)
    ? $c->render(text => 'ok', status => 200)
    : $c->render(text => 'not ok', status => 404);
};

=head3 POST /group/:group/:user

Add the given user (:user) to the given group (:group).
Returns 200 ok on success, 404 not ok on failure.

=cut

post '/group/:group/:user' => sub {
    my($c) = @_;
    $c->refresh;
    my $users = $c->authz->users_in_group($c->stash('group'));
    return $c->render(text => 'not ok', status => 404) unless defined $users;
    push @$users, $c->stash('user');
    @$users = uniq @$users;
    $c->authz->update_group($c->param('group'), join(',', @$users))
    ? $c->render(text => 'ok', status => 200)
    : $c->render(text => 'not ok', status => 404);
};

=head3 DELETE /group/:group/:user

Remove the given user (:user) from the given group (:group).
Returns 200 ok on success, 404 not ok on failure.

=cut

del '/group/:group/:user' => sub {
    my($c) = @_;
    $c->refresh;
    my $users = $c->authz->users_in_group($c->stash('group'));
    return $c->render(text => 'not ok', status => 404) unless defined $users;
    my $user = $c->stash('user');
    @$users = grep { $_ ne $user } @$users;
    $c->authz->update_group($c->param('group'), join(',', @$users))
    ? $c->render(text => 'ok', status => 200)
    : $c->render(text => 'not ok', status => 404);
};

=head3 POST /grant/#group/:action1/(*resource)

Grant access to the given group (#group) so they can perform the given action (:action1)
on the given resource (*resource).  Returns 200 ok on success, 404 not ok on failure.

=cut

post '/grant/#group/:action1/(*resource)' => sub {
    my $c = shift;
    $c->refresh;
    my($group, $action, $resource) = map { $c->stash($_) } qw( group action1 resource );
    $c->authz->grant($group, $action, $resource)
    ? $c->render(text => 'ok',     status => 200)
    : $c->render(text => 'not ok', status => 404);
};

=head3 DELETE /grant/#group/:action1/(*resource)

Revoke permission to the given group (#group) to perform the given action (:action1) on
the given resource (*resource).  Returns 200 ok on success, 404 not ok on failure.

=cut

del '/grant/#group/:action1/(*resource)' => sub {
    my($c) = @_;
    $c->refresh;
    my($group, $action, $resource) = map { $c->stash($_) } qw( group action1 resource );
    $c->authz->revoke($group, $action, $resource)
    ? $c->render(text => 'ok',     status => 200)
    : $c->render(text => 'not ok', status => 404);
};

=head3 GET /grant

Get the list of granted permissions.

=cut

get '/grant' => sub {
    my($c) = @_;
    $c->stash->{autodata} = $c->authz->granted;
};

=head2 Change Password routes

These routes are available to users authenticates and authorized to perform
the 'change_password' action.  They will return

=over 4

=item * 401

If no credentials are provided

=item * 403

If the user is unauthorized.

=item * 503

If the PlugAuth server cannot reach itself or the deligated PlugAuth server.

=back

=head3 POST /user/#user

Change the password of the given user (#user).  The C<password> is provided as
an autodata argument (JSON, YAML, form data, etc.).  Returns 200 ok on success,
403 not ok on failure.

=cut

authenticate;
authorize 'change_password';

post '/user/#user' => sub {
    my($c) = @_;
    $c->refresh;
    $c->parse_autodata;
    my $user = $c->param('user');
    my $password = eval { $c->stash->{autodata}->{password} } || '';
    delete $c->stash->{autodata};
    $c->auth->change_password($user, $password)
    ? $c->render(text => 'ok', status => 200)
    : $c->render(text => 'not ok', status => 403);
};

1;

=head1 SEE ALSO

L<PlugAuth>

=cut
