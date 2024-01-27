# Getting the desired version of the P4 code

You need a copy of the p4-guide repo, or at least one file of it that
is `#include`'d from `bsic_ipv6.p4`:

```bash
$ git clone https://github.com/jafingerhut/p4-guide
$ git clone https://github.com/jafingerhut/cram
$ cd cram
$ git checkout makefiles-do-open-source-syntax-check-compiles
$ git log -n 1 | cat
commit a1b7edeab2060e8cc659a51a5d8b63c94bd7db99
Author: Andy Fingerhut <andy_fingerhut@alum.wustl.edu>
Date:   Sat Jan 27 20:48:44 2024 +0000

    Add 10 sets of table sizes for bsic_ipv6.p4
```

Set up environment variables `SDE` and `SDE_INSTALL` as is typically
recommended for the Tofino SDE.

Assign a value to the environment variable `P4GUIDE` that is where
your copy of the `p4-guide` repo is, e.g.:

```bash
export P4GUIDE=$HOME/p4-guide
```


# Desired compilation runs and output

Only results for compilation with Tofino2 are desired.  The program
might not even fit on Tofino1 -- I do not recall right now for
certain, as it has been several months since I ran the results before.

```bash
$ cd cram/bsic
$ ../scripts/compile-tofino2.sh bsic_ipv6.p4
```
