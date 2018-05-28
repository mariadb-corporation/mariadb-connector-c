#!/bin/bash

# don't pull in submodules. We want the latest C/C as libmariadb
git config cmake.update-submodules no

# get latest server
git clone -b 10.3 https://github.com/mariadb/server ../workdir-server

# copy C/C into libmariadb in server
ls -l ../workdir-server/libmariadb
cp -r . ../workdir-server/libmariadb

# build latest server with latest C/C as libmariadb
# skip to build some storage engines to speed up the build
cd ../workdir-server
cmake -DPLUGIN_MROONGA=NO -DPLUGIN_ROCKSDB=NO -DPLUGIN_SPIDER=NO -DPLUGIN_TOKUDB=NO
make -j9
