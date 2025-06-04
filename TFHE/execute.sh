#!/bin/bash
git clone https://github.com/tfhe/tfhe.git
cd tfhe
mkdir build
cd build
cmake ../src -Wno-dev
make
make install
cd ../..
g++ -w results_TFHE.cpp sha256.c -o results_TFHE -ltfhe-spqlios-fma -std=c++11
./results_TFHE
