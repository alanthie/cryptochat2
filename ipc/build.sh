#!/bin/bash

cd src
make

cd ../cpp
make

cd ../examples/linux
make

cd ../cpp/linux
make
