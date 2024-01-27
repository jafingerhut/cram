# Getting the desired version of the P4 code

You need a copy of the p4-guide repo, or at least one file of it that
is `#include`'d from `bsic_ipv6.p4`:

```bash
$ git clone https://github.com/jafingerhut/p4-guide
$ git clone https://github.com/jafingerhut/cram
$ cd cram
$ git checkout makefiles-do-open-source-syntax-check-compiles
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
$ ../scripts/compile-tofino2.sh bsic_ipv6.p4 -DTABLE_SIZES_3
```

We would like at least the total number of TCAM and SRAM pages used in
ingress and egress, as well as total number of stages in ingress and
egress.  If it is quick enough for you, a screenshot of the P4 Insight
page that shows the number of TCAM pages and SRAM pages broken down by
each ingress stage, and each egress stage, would also be nice.

Then repeat the above for each of the preprocessor symbols
`-DTABLE_SIZES_4` through `-DTABLE_SIZES_11`, for a total of 9
variants of the program.
