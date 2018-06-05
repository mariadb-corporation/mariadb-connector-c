#!/bin/bash

# run mtr protocol tests
cd ../workdir-server/mysql-test
./mysql-test-run.pl --suite=main --ps-protocol --parallel=4
