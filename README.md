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
