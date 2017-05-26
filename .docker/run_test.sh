#!/bin/bash

##########################################################
#wait for running db
##########################################################

sleep 5
echo 'wait for db initialisation'
mysql=( mysql -uroot --password=pwd --host=db)


for i in {30..0}; do
    if echo 'SELECT 1' | "${mysql[@]}" &> /dev/null; then
        break
    fi
    echo 'db init process in progress...'
    sleep 1
done

if [ "$i" = 0 ]; then
    echo >&2 'MySQL init process failed.'
    exit 1
fi

echo 'db init done'

##########################################################
#basic information
##########################################################

export MYSQL_TEST_USER=root
export MYSQL_TEST_HOST=db
export MYSQL_TEST_PASSWD=pwd
export MYSQL_TEST_DB=test
export MYSQL_TEST_PORT=3306


##########################################################
#run tests
##########################################################
cd /cc/build/unittest/libmariadb
ctest -V
