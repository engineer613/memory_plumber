#!/bin/bash

MEM_PLUMBER_SRC="./mem_plumber.cpp"
APP_SRC="./leaky_example.cpp"

# Compile memplumber library with the right debug symbols, flags and link them to dl and pthread libs
g++ -g -fPIC -shared -o libmemplumber.so $MEM_PLUMBER_SRC -ldl -rdynamic -lpthread

# Compile application in question with debug symbols
g++ -g -o leaky_application $APP_SRC

LD_PRELOAD=./libmemplumber.so ./leaky_application 





