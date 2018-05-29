#!/bin/bash

# run mtr main test suite
cd ../workdir-server/mysql-test
./mysql-test-run.pl --suite=main --parallel=4
