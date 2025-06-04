#!/bin/bash
g++ -w results_TFHE.cpp sha256.c -o results_TFHE -ltfhe-spqlios-fma -std=c++11
./results_TFHE
