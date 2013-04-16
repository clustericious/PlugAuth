
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  "build_requires" => {
    "File::HomeDir" => 0,
    "Module::Build" => "0.3601",
    "Mojo::JSON" => 0,
    "Test::Differences" => 0,
    "Test::Mojo" => 0,
    "Test::More" => 0
  },
  "configure_requires" => {
    "Module::Build" => "0.3601"
  },
  "dist_abstract" => "Pluggable authentication and authorization server.",
  "dist_author" => [
    "Graham Ollis <gollis\@sesda3.com>"
  ],
  "dist_name" => "PlugAuth",
  "dist_version" => "0.10",
  "license" => "perl",
  "module_name" => "PlugAuth",
  "recommends" => {},
  "recursive_test_files" => 1,
  "requires" => {
    "Clone" => 0,
    "Clustericious" => "0.9909",
    "Clustericious::App" => 0,
    "Clustericious::Commands" => 0,
    "Clustericious::Config" => 0,
    "Clustericious::Log" => 0,
    "Clustericious::RouteBuilder" => 0,
    "Crypt::PasswdMD5" => 0,
    "Exporter" => 0,
    "Fcntl" => 0,
    "File::HomeDir::Test" => 0,
    "File::Spec" => 0,
    "File::Temp" => 0,
    "File::Touch" => 0,
    "File::stat" => 0,
    "FindBin" => 0,
    "IO::File" => 0,
    "List::MoreUtils" => 0,
    "Log::Log4perl" => 0,
    "Mojo::Base" => 0,
    "Mojo::ByteStream" => 0,
    "Mojolicious::Plugins" => 0,
    "Role::Tiny" => 0,
    "Role::Tiny::With" => 0,
    "Test::Builder" => 0,
    "Text::Glob" => 0,
    "YAML" => 0,
    "autodie" => 0,
    "perl" => "v5.10.0"
  },
  "script_files" => [
    "bin/plugauth"
  ]
);


my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
