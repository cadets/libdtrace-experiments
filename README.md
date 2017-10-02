### BUILD ###

There are two types of builds for libdtrace-core. One is meant to be built with
tests, while the other is aimed for future extensions to libdtrace-core that
allow it to be linked into different processes in order to perform various types
of tracing.

The current recommended way to build the project is with the tests:

```
mkdir build && cd build
cmake -D BUILD_TESTS=yes .. -GNinja
ninja
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

In fuzzing mode, each of the tools has to be built using afl-clang in order to
get the necessary instrumentation in the binaries so that fuzzing can be more
effective.

The fuzzers should be run manually using AFL.

### TEST ###

The tests can be run using

```
ninja test
```

in the build directory.

If FileCheck is installed, the compiler tests will also be set up and run.
Similarly, if ctfconvert and ctfdump are present on the system, the CTF tests
will be built and run automatically with the use of the above command.

