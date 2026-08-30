# Sesam's secret repo

Our own secrets required to sign releases.

## How it was build

```
$ sesam init
$ sesam rm README.md
$ sesam tell --recipient github:Johnny2210 --group admin
$ sesam tell --recipient github:adelbables --group admin
$ sesam add release_signing.key
```
