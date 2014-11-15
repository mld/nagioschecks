#!/usr/bin/perl -w
# Author: Mikael Löfstrand <micke@lofstrand.net>
#
# Copyright (c) 2014-11-15, Mikael Löfstrand
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;
use POSIX;
use Getopt::Long qw(:config bundling);

sub process_cert();

my $filename;
my $verbose = 0;
my $criticaldays = 30;
my $warningdays  = 90;
my $printcert = 0;
my $help = 0;
my $result = GetOptions(
  "f|filename:s" => \$filename,
  "w|warning:i"  => \$warningdays,
  "c|critical:i" => \$criticaldays,
  "v|verbose+"   => \$verbose,
  "p|printcert!" => \$printcert,
  "h|help!"      => \$help,
);

print "verbose:      $verbose\n";
print "filename:     $filename\n" if $filename;
print "help:         $help\n";
print "printcert:    $printcert\n";
print "criticaldays: $criticaldays\n";
print "warningdays:  $warningdays\n";

my $now      = `date +%s`;
my $warning  = $now + $warningdays  * 86400;
my $critical = $now + $criticaldays * 86400;
my $ifile    = "";
my $thisfile = "";
my $crit     = 0;
my $warn     = 0;
my $ok       = 0;

if($help) {
  my $USAGE = <<"USAGE";
Usage: certcheck.pl [-w <days>|-c <days>|-v|-vv|-vvv|-p|-h|-f <cacertfile>]

Options:
  -f, --filename <file>	Filename to check for certificates, or if not given, read from STDIN
  -w, --warning <days>	Days a certificate needs to be valid before a warning is given.
  -c, --critical <days>	Days a certificate needs to be valid before a critical is given.
  -v, --verbose		Shows more information each time it is given.
  -p, --printcert	In combination with -v, prints the certificate raw data.
  -h, --help		Prints this message.

USAGE

  die $USAGE;
}

if($filename) {
  open IN, "<$filename" or die("Unable to open \"$filename\"\n");
  while(<IN>) { 
    $ifile .= $_; 
    $thisfile .= $_;
    if($_ =~ /^\-+END(\s\w+)?\sCERTIFICATE\-+$/) {
      &process_cert($thisfile);
      $thisfile = "";
    }
  }
  close IN;
}
else {
  while(<STDIN>) { 
    $ifile .= $_; 
    $thisfile .= $_;
    if($_ =~ /^\-+END(\s\w+)?\sCERTIFICATE\-+$/) {
      &process_cert($thisfile);
      $thisfile = "";
    }
  }
} 

if($crit > 0) {
  print "CRITICAL - $crit certificates expires within $criticaldays days!\n";
  exit(2);
}
elsif($warn > 0) {
  print "WARNING - $warn certificates expires within $warningdays days!\n";
  exit(1);
}
elsif($ok > 0) {
  print "OK - no certificates expires within $warningdays days.\n";
  exit(0);
}
else {
  print "UNKNOWN - Something probably went wrong.\n";
  exit(3);
}

sub process_cert() {
  $thisfile = shift;

  my $currentcert = `echo "$thisfile" | openssl x509 -noout -issuer -subject -enddate`;
  $currentcert =~ /issuer=(.*)\nsubject=(.*)\nnotAfter=(.*)/;

  my $issuer = $1;
  my $subject = $2;
  my $enddate = $3;
  my $notAfter = `date +%s -d '$3'`;

  my $expiresindays = floor(($notAfter - $now) / 86400);
  if($notAfter < $critical) {
    print "CRIT cert expires in $expiresindays days ($enddate): $subject!\n" if $verbose > 0;
    print $thisfile if $verbose > 0 and $printcert;
    $crit++;
  }
  elsif($notAfter < $warning) {
    print "WARN cert expires in $expiresindays days ($enddate): $subject...\n" if $verbose > 1;
    print $thisfile if $verbose > 1 and $printcert;
    $warn++;
  }
  else {
    print "OK enddate for certificate $subject.\n" if $verbose > 2;
    print $thisfile if $verbose > 2 and $printcert;
    $ok++;
  }
}

