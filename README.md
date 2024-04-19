# Post-quantum PAKE C Implementation

This repository contains the C implementation of the post-quantum password-authenticated key exchange algorithms CAKE and OCAKE.

This work is based on [the paper introducing both algorithms](https://eprint.iacr.org/2023/470), as well as several implementation choices regarding the ideal cipher model.

This implementation is based on the [`PQClean`](https://github.com/PQClean/PQClean) project.

OpenSSL and GMP are also dependencies for this project and should be installed on your system.

## Installation

### Installation of PQClean

```shell
cd PQClean
git submodule update --init --recursive
```

## Compilation

```
make -j 4
```
