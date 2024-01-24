# This Makefile is only intended to be used to check the syntax of the
# P4 source files in this directory using then open source p4test
# command that is part of the open source P4 compiler in
# https://github.com/p4lang/p4c
#
# If you wish to compile these programs using the Tofino P4 compiler,
# see the scripts compile-tofino1.sh and compile-tofino2.sh in the
# scripts directory.

include ../Makefile

syntaxcheck: bsic_ipv6.p4
	p4test $(P4TESTFLAGS) bsic_ipv6.p4
