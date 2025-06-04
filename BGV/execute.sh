#!/bin/bash
git clone https://github.com/microsoft/SEAL.git
cd SEAL
cmake -S . -B build
cmake --build build
cmake --install build
cd ..
cmake . -Wno-dev
make
./results_BGV
