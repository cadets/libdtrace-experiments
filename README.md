### BUILD ###

There are two build modes for libdtrace-core and it's components. The first mode
is designed to be used by programs that have been built with the library and
intend to use it in a real environment. This can be accomplished by building
libdtrace-core without any flags as such:

```
make
```

The other way to build libdtrace-core is for testing purposes. This is not
recommeded for a production environment due to the amount of symbols it exposes
and thus introduced LD_PRELOAD type vulnerabilities and additional overhead.

However, for testing purposes, in order to get access to a couple of the
internal functions that aid in unit testing and fuzzing libdtrace-core, one can
use:

```
make -D_DTRACE_TESTS
```

### FUZZ ###

In order for the fuzzing to work, one must install AFL by running the following
command:

```
pkg install security/afl
```

The directory structure of the fuzzers from the perspective of the
`libdtrace-core-fuzz` directory is as follows:

```
.
├── fuzz01
│   ├── in
│   │   ├── 1
│   │   └── 2
│   ├── fuzz01.c
│   └── Makefile
├── fuzz02
│   ├── in
│   │   ├── 1
│   │   ├── 2
│   │   ├── 3
│   │   ├── 4
│   │   └── 5
│   ├── fuzz02.c
│   └── Makefile
│	... 
└── Makefile
```

In fuzzing mode, each of the tools is built using afl-clang in order to get
the necessary instrumentation in the binaries so that fuzzing can be more
effective.

In order to start the fuzz, fire up `tmux` and run:
```
./dtfuzz
```

`tmux` will not be a dependency in the future, but is here for convenience
purposes for the moment.

In addition to that, all of the regular AFL operations are supported, including
parallel fuzzing and distributed fuzzing, but there is no "easy" way to run that
currently and has to be done manually.

### TEST ###

In order to run tests, the kyua package has to be installed, which can be done
on FreeBSD using:

```
pkg install devel/kyua
```

Following that, running tests can be done with the use of

```
make test
```

The reports can then be generated in two formats, the standard kyua report, as
well as JUnit using the `report` and `junit` targets:

```
make report
make junit
```

Should the tests fail, it's possible to gather the information on a test case
through the use of

```
make debugtest TEST=<specification>
```

This requires for the gdb package to be installed.
