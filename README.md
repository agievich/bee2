Bee2: a cryptographic library
=============================

![](img/bee2.png)

[![Build Status](https://travis-ci.org/agievich/bee2.svg?branch=master)](https://travis-ci.org/agievich/bee2)
[![Coverity Static Analysis](https://scan.coverity.com/projects/8544/badge.svg)](https://scan.coverity.com/projects/agievich-bee2)
[![Coverage Analysis](https://codecov.io/gh/agievich/bee2/coverage.svg?branch=master)](https://codecov.io/gh/agievich/bee2?branch=master)

What is Bee2?
-------------

Bee2 is a cryptographic library which implements cryptographic 
algorithm and protocols standardized in Belarus. 
Bee2 fully supports the following standards 
(see [apmi.bsu.by/resources/std.html](http://apmi.bsu.by/resources/std.html)):

1. STB 34.101.31 (belt): data encryption and integrity algorithms.
2. STB 34.101.45 (bign): digital signature and key transport algorithms 
   over elliptic curves.
3. STB 34.101.47 (brng): cryptographic algorithms of pseudorandom number 
   generation + one-time passwords.
4. STB 34.101.60 (bels): secret sharing algorithms.
5. STB 34.101.66 (bake): key establishment protocols over elliptic curves. 
6. STB 34.101.77 (bash): sponge-based algorithms. 

Additionally, Bee2 implements digital signature algorithms standardized in 
Russia and Ukraine.

Build
-----
```
mkdir build
cd build
cmake [-DCMAKE_BUILD_TYPE={Release|Debug|Coverage|ASan|ASanDbg|MemSan|MemSanDbg|Check}]\
      [-DBUILD_FAST=ON]\
      [-DBASH_PLATFORM={BASH_32|BASH_64|BASH_AVX2|BASH_AVX512|BASH_NEON}]\
      ..
make
[make test]
[make install]
```

Build types (`Release` by default):
   
*  `Coverage` — test coverage,
*  `ASan`, `ASanDbg` — [address sanitizer](http://en.wikipedia.org/wiki/AddressSanitizer),
*  `MemSan`, `MemSanDbg` — [memory sanitizer](http://code.google.com/p/memory-sanitizer/),
*  `Check` — strict compile rules.

The `BUILD_FAST` option (`OFF` by default) switches from safe (constant-time) 
functions to fast (non-constant-time) ones.

The `BASH_PLATFORM` option (`BASH_64` by default) requests to use a specific 
implementation of the STB 34.101.77 algorithms optimized for a given hardware platform. 
The request may be rejected if it conflicts with other options.

License
-------

Bee2 is released under the terms of the GNU General Public License version 3
(GNU GPLv3). See [LICENSE](LICENSE) for more information.

What is the logo?
-----------------

The logo of Bee2 is taken from a self-portrait engraving by 
[Francysk Skaryna](https://en.wikipedia.org/wiki/Francysk_Skaryna), 
the famous Belarusian medieval printer, enlightener, translator and writer. 
The engraving is full of riddles, mysteries and cryptograms. One version 
is that a bee in the right-bottom corner, our logo, designates the 
constellation known as *Apes* (Latin for bees) in Skaryna's time. This 
constellation was later renamed in *Musca Borelias* (Latin for northern 
fly) and then absorbed by *Aries*.

