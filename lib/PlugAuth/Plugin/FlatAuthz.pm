package PlugAuth::Plugin::FlatAuthz;

# ABSTRACT: Authorization using flat files for PlugAuth
# VERSION

=head1 SYNOPSIS

In your /etc/PlugAuth.conf

 ---
 url: http://localhost:1234
 group_file: /etc/plugauth/group.txt
 resource_file: /etc/plugauth/resource.txt
 host_file: /etc/plugauth/host.txt

touch the storage files:

 % touch /etc/plugauth/group.txt \
         /etc/plugauth/resource.txt \
         /etc/plugauth/host.txt

Start PlugAuth:

 % plugauth start

=head1 DESCRIPTION

This is the default Authorization plugin for L<PlugAuth>.  It is designed to work closely
with L<FlatAuth> which is the default Authentication plugin.

This plugin provides storage for groups, hosts and access control for PlugAuth.  In addition
it provides a mechanism for PlugAuth to alter the group, host and access control databases.

=head1 CONFIGURATION

=head2 group_file

The group file looks similar to a standard UNIX /etc/group file.  Entries can be changed using
either your favorite editor, or by using L<PlugAuth::Client>.  In this example there is a group
both to which both  bob and alice belong:

 both: alice, bob

Group members can be specified using a glob (see L<Text::Glob>) which match against the set of all users:

 all: *

Each user automatically gets his own group, so if there is a users named bob and alice, this is 
unnecessary:

 alice: alice
 bob: bob

=head2 resource_file

Each line of resource.txt has a resource, an action (in parentheses), and then a list of users or groups.  
The line grants permission for those groups to perform that action on that resource :

 /house/door (enter) : alice, bob
 /house/backdoor (enter) : both
 /house/window (break) : alice
 /house (GET) : bob

=head2 host_file

The host file /etc/pluginauth/host.txt looks like this :

 192.168.1.99:trusted
 192.168.1.100:trusted

The IP addresses on the right represent hosts from which authorization should succeed.

=cut

use strict;
use warnings;
use v5.10;
use Log::Log4perl qw/:easy/;
use Text::Glob qw/match_glob/;
use Fcntl qw/ :flock /;
use Clone qw( clone );
use Crypt::PasswdMD5 qw( unix_md5_crypt apache_md5_crypt );
use Role::Tiny::With;
use File::Touch;

with 'PlugAuth::Role::Plugin';
with 'PlugAuth::Role::Authz';
with 'PlugAuth::Role::Refresh';
with 'PlugAuth::Role::Flat';

our %all_users;
our %groupUser;           # $groupUser{$group}{$user} is true iff $user is in $group
our %userGroups;          # $userGroups{$user}{$group} is true iff $user is in $group
our %resourceActionGroup; # $resourceActionGroup{$resource}{$action}{$group} is true iff $group can do $action on $resource
our %actions;             # All defined actions $actions{$action} = 1;
our %hostTag;             # $hostTag{$host}{$tag} is true iff $user has tag $tag

=head1 METHODS

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>refresh

Refresh the data (checks the files, and re-reads if necessary).

=cut

sub refresh {
    my($class) = @_;
    my $config = $class->global_config;
    if ( has_changed( $config->group_file ) ) {
        %all_users = map { $_ => 1 } __PACKAGE__->app->auth->all_users;
        %groupUser = ();
        my %data = __PACKAGE__->read_file( $config->group_file, nest => 1 );
        for my $k (keys %data) {
            my %users;
            for my $v (keys %{ $data{$k} }) {
               my @matches = match_glob( $v, keys %all_users);
               next unless @matches;
               @users{ @matches } = (1) x @matches;
            }
            $groupUser{$k} = \%users;
        }
        %userGroups = __PACKAGE__->_reverse_nest(%groupUser);
    }
    if ( has_changed( $config->resource_file ) ) {
        %all_users = map { $_ => 1 } __PACKAGE__->app->auth->all_users;
        %resourceActionGroup = __PACKAGE__->read_file( $config->resource_file, nest => 2 );

        foreach my $resource (keys %resourceActionGroup)
        {
            # TODO: maybe #g for group
            if($resource =~ /#u/) {
                my $value = delete $resourceActionGroup{$resource};

                foreach my $user (keys %all_users) {
                    my $new_resource = $resource;
                    my $new_value = clone $value;

                    $new_resource =~ s/#u/$user/g;

                    foreach my $users (values %$new_value) {
                        if(defined $users->{'#u'}) {
                            delete $users->{'#u'};
                            $users->{$user} = 1;
                        }
                    }

                    $resourceActionGroup{$new_resource} = $new_value;
                }
            }
        }

        %actions = map { map { $_ => 1} keys %$_ } values %resourceActionGroup;
    }
    my $h = $config->host_file(default => '');
    if ( ( $h ) && has_changed( $h ) ) {
        %hostTag = __PACKAGE__->read_file( $h, nest => 1 );
    }
    1;
}

sub init
{
    # When the user list has changed, the group files need to be reloaded, because
    # each user has his/her own group, so we touch the group file

    my($self) = @_;
    my $touch = File::Touch->new(
        mtime_only => 1,
        no_create => 1,
    );
    my @list = ($self->app->config->group_file(default => []));
    
    $self->app->on(user_list_changed => sub {
        $touch->touch(@list);
    });
}

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>can_user_action_resource( $user, $action, $resource )

If $user can perform $action on $resource, return a string containing
the group and resource that permits this.  Otherwise, return false.

=cut

sub can_user_action_resource {
    my ($class, $user,$action,$resource) = @_;
    $user = lc $user;
    my $found;
    GROUP:
    for my $group ( $user, keys %{ $userGroups{$user} } ) {
        # check exact match on the resource so / will match
        if($resourceActionGroup{$resource}{$action}{$group}) {
            $found = "group: $group resource: $resource";
            last GROUP;
        }
        for my $subresource (__PACKAGE__->_prefixes($resource)) {
            next unless $resourceActionGroup{$subresource}{$action}{$group};
            $found = "group: $group resource: $subresource";
            last GROUP;
        }
    }
    return $found;
}

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>match_resources( $regex )

Given a regex, return all resources that match that regex.

=cut

sub match_resources {
    my($class, $resourceregex) = @_;
    return (grep /$resourceregex/, keys %resourceActionGroup);
}

sub _reverse_nest {
    my $class = shift;
    # Given a nested hash ( a => b => c), return one with (b => a => c);
    my %h = @_;
    my %new;
    while (my ($a,$bc) = each %h) {
        while (my ($b,$c) = each %$bc) {
            $new{$b}{$a} = $c;
        }
    }
    return %new;
}

sub _prefixes {
    my $class = shift;
    # Given a string "/a/b/c/d" return an array of prefixes :
    #  "/", "/a", "/a/b", /a/b/c", "/a/b/c/d"
    my $str = shift;
    my @p = split /\//, $str;
    my @prefixes = ( map { '/'. join '/', @p[1..$_] } 0..$#p );
    return @prefixes;
}

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>host_has_tag( $host, $tag )

Returns true if the given host has the given tag.

=cut

sub host_has_tag {
    my ($class, $host, $tag) = @_;
    return exists($hostTag{$host}{$tag});
}

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>actions

Returns a list of actions.

=cut

sub actions {
    return sort keys %actions;
}

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>groups_for_user( $user )

Returns the groups the given user belongs to as a list ref.
Returns undef if the user does not exist.

=cut

sub groups_for_user {
    my $class = shift;
    my $user = shift or return ();
    $user = lc $user;
    return unless $all_users{$user};
    return [ sort $user, keys %{ $userGroups{ $user } || {} } ];
}

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>all_groups

Returns a list of all groups.

=cut

sub all_groups {
    return sort keys %groupUser;
}

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>users_in_group( $group )

Return the list of users (as an array ref) that belong 
to the given group.  Each user belongs to a special 
group that is the same as their user name and just 
contains themselves, and this will be included in the 
list.

Returns undef if the group does not exist.

=cut

sub users_in_group {
    my $class = shift;
    my $group = shift or return ();
    return unless defined $groupUser{$group};
    return [keys %{ $groupUser{$group} }];
}

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>create_group( $group, $users )

Create a new group with the given users.  $users is a comma
separated list of user names.

=cut

sub create_group
{
    my($class, $group, $users) = @_;

    unless(defined $group) {
        WARN "Group not provided";
        return 0;
    }

    if(defined $groupUser{$group}) {
        WARN "Group $group already exists";
        return 0;
    }

    $users = '' unless defined $users;

    my $filename = $class->global_config->group_file;

    eval {
        use autodie;

        open my $fh, '>>', $filename;

        eval { flock $fh, LOCK_EX };
        WARN "cannot lock $filename - $@" if $@;

        print $fh "$group : $users\n";

        close $fh;
    };

    ERROR "modifying file $filename: $@" if $@;
    mark_changed($filename);
    return 1;
}

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>delete_group( $group )

Delete the given group.

=cut

sub delete_group
{
    my($class, $group) = @_;

    unless($group && defined $groupUser{$group}) {
        WARN "Group $group does not exist";
        return 0;
    }

    my $filename = $class->global_config->group_file;

    eval {
        use autodie;

        my $buffer = '';

        open my $fh, '+<', $filename;

        eval { flock $fh, LOCK_EX };
        WARN "cannot lock $filename - $@" if $@;

        while(<$fh>) {
            my($thisgroup, $password) = split /\s*:/;
            next if $thisgroup eq $group;
            $buffer .= $_;
        }

        seek $fh, 0, 0;
        truncate $fh, 0;
        print $fh $buffer;

        close $fh;
    };

    ERROR "modifying file $filename: $@" if $@;
    mark_changed($filename);
    return 1;
}

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>update_group( $group, $users )

Update the given group, setting the set of users that belong to that
group.  The existing group membership will be replaced with the new one.
$users is a comma separated list of user names.

=cut

sub update_group
{
    my($class, $group, $users) = @_;

    unless($group && defined $groupUser{$group}) {
        WARN "Group $group does not exist";
        return 0;
    }

    return 1 unless defined $users;

    my $filename = $class->global_config->group_file;

    eval {
        use autodie;

        my $buffer = '';

        open my $fh, '+<', $filename;

        eval { flock $fh, LOCK_EX };
        WARN "cannot lock $filename - $@" if $@;

        while(<$fh>) {
            my($thisgroup, $password) = split /\s*:/;
            s{:.*$}{: $users} if $thisgroup eq $group;
            $buffer .= $_;
        }

        seek $fh, 0, 0;
        truncate $fh, 0;
        print $fh $buffer;

        close $fh;
    };

    ERROR "modifying file $filename: $@" if $@;
    mark_changed($filename);
    return 1;
}

=head2 PlugAuth::Plugin::FlatAuthz-E<gt>grant( $group, $action, $resource )

Grant the given group or user the authorization to perform the given
$action on the given $resource.

=cut

sub grant
{
    my($class, $group, $action, $resource) = @_;

    unless($group && (defined $groupUser{$group} || defined $all_users{$group})) {
        WARN "Group (or user) $group does not exist";
        return 0;
    }

    $resource = '/' . $resource unless $resource =~ /\//;

    if($resourceActionGroup{$resource}->{$action}->{$group})
    {
      WARN "grant already added $group $action $resource";
      return 1;
    }

    my $filename = $class->global_config->resource_file;

    eval {
        use autodie;

        my $buffer = '';

        open my $fh, '>>', $filename;

        eval { flock $fh, LOCK_EX };
        WARN "cannot lock $filename - $@" if $@;

        print $fh "$resource ($action) : $group\n";

        close $fh;
    };

    ERROR "modifying file $filename: $@" if $@;
    mark_changed($filename);
    return 1;
}

1;

=head1 SEE ALSO

L<PlugAuth>, L<PlugAuth::Plugin::FlatAuth>

=cut
