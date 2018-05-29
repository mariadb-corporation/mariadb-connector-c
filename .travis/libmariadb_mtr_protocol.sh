#!/bin/bash

# run mtr protocol tests
cd ../workdir-server/mysql-test
./mysql-test-run.pl --ps-protocol --parallel=4
