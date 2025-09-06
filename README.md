# sodo

sodo - unsafe(\*not rust, no passwd) sudo/doas

Based on a survey of Linux users around me, I found that most people neither set
passwords for sudo or doas nor use advanced features. Therefore, I believe it's
necessary to sreamline the requirements and focus only on the core functionality,
in order to keep the project simple and highly maintainable.

## Usage

```bash
# suid
$ sodo id -u
0
```

```bash
# env
$ sodo FOO=BAR printenv FOO
BAR
```

```bash
# edit
$ sodo -e /etc/apk/world
```

## Init

```bash
$ su -c "busybox adduser $USER wheel"
```

## TODO

- More LOG and ERR(errno) outputs
- Integeation tests
- Manpage(needed?)
- Debug? Valgrind?
- Makefile

## LICENSE

MIT

