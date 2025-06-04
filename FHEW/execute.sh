#!/bin/bash
git clone https://github.com/lducas/FHEW.git
cp results_FHEW.cpp sha256.c sha256.h FHEW
cd FHEW
make
make install
g++ -w -ansi -Wall -O3 -o results_FHEW results_FHEW.cpp sha256.c -L. -lfhew -lfftw3 -std=c++11
./results_FHEW
