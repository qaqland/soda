# sodo

sodo - unsafe(\*not rust, no passwd) sudo/doas

## Usage

```bash
$ sodo id -u
0
```

```bash
$ sodo FOO=BAR printenv FOO
BAR
```

```bash
$ sodo -e /etc/apk/world
```

## Init

```bash
$ su -c "busybox adduser $USER wheel"
```

## TODO

- More LOG and ERR outputs
- More integeation tests
- Manpage(needed?)

## LICENSE

MIT

