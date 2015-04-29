Bee2: a cryptographic library
=============================

What is Bee2?
-------------

Bee2 is a cryptographic library which implements cryptographic 
algorithm and protocols standardized in Belarus. 
Bee2 fully supports the following standards:

1. STB 34.101.31 (belt): data encryption and integrity algorithms.
2. STB 34.101.45 (bign): digital signature and key transport algorithms 
   based on elliptic curves.
3. STB 34.101.47 (brng): cryptographic algorithms of pseudorandom number 
   generation.
4. STB 34.101.60 (bels): secret sharing algorithms.
5. STB 34.101.66 (bake): key establishment protocols based on elliptic 
   curves. 

You can found these standards at 
[apmi.bsu.by/resources/std.html](http://apmi.bsu.by/resources/std.html).

Additionally Bee2 implements digital signature algorithms standardized in 
Russia and Ukraine.

Build
-----

### Prepare build

    mkdir build
    cd build
    cmake  ..

### Build types

#### Debug

    cmake -DCMAKE_BUILD_TYPE=Debug ..

#### Coverage

    cmake -DCMAKE_BUILD_TYPE=Coverage ..

#### ASan (AddressSanitizer)

    cmake -DCMAKE_BUILD_TYPE=ASan ..
    cmake -DCMAKE_BUILD_TYPE=ASanDbg ..

#### MemSan (MemorySanitizer)

    cmake -DCMAKE_BUILD_TYPE=MemSan ..
    cmake -DCMAKE_BUILD_TYPE=MemSanDbg ..

#### Check (strict complile rules)

    cmake -DCMAKE_BUILD_TYPE=Check ..
    cmake -DCMAKE_BUILD_TYPE=CheckFull ..

### Build

    make

### Test

    make test

### Install

    make install

License
-------

Bee2 is released under the terms of the GNU General Public License version 3
(GNU GPLv3). See [LICENSE](LICENSE) for more information.
