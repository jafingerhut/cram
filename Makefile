# This Makefile is only intended to be used to check the syntax of P4
# source files, using then `p4test` command that is part of the open
# source P4 compiler in https://github.com/p4lang/p4c
#
# If you wish to compile these programs using the Tofino P4 compiler,
# see the scripts `compile-tofino1.sh` and `compile-tofino2.sh` in the
# `scripts` directory.

# P4GUIDE is the Location on your system of a clone of repo
# https://github.com/jafingerhut/p4-guide
P4GUIDE=$(HOME)/p4-guide

# OPENTOFINO is the Location on your system of a clone of repo
# https://github.com/barefootnetworks/Open-Tofino
OPENTOFINO=$(HOME)/Open-Tofino

P4TESTFLAGS=-DTOFINO1 -DOPENTOFINO_INCLUDES -I $(P4GUIDE)/stdlib -I $(OPENTOFINO)/share/p4c/p4include 
