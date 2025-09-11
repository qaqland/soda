# soda

soda - unsafe(\*not rust, no passwd) sudo/doas

Allow users in a specific group to execute a command as root.

## Usage

```bash
$ su -c "busybox adduser <USER> <GROUP>"
```

```bash
# suid
$ soda id -u
0
```

```bash
# env
$ soda FOO=BAR printenv FOO
BAR
```

```bash
# edit
$ soda -e /etc/apk/world
```

## Install

Please read the source code and figure out the installation on your own.

## TODO

- Integeation tests
- Manpage(needed?)
- Debug? Valgrind?

## LICENSE

MIT

