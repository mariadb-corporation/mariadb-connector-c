#!/bin/bash

set -x
set -e

export MYSQ_GPG_KEY=5072E1F5

remove_mysql(){
    service mysql stop
    apt-get remove --purge mysql-server mysql-client mysql-common
    apt-get autoremove
    apt-get autoclean
    rm -rf /etc/mysql||true
    rm -rf /var/lib/mysql||true
}

if [ -n "$MYSQL_VERSION" ]
then

    remove_mysql

    tee /etc/apt/sources.list.d/mysql.list << END
deb http://repo.mysql.com/apt/ubuntu/ precise mysql-$MYSQL_VERSION
deb-src http://repo.mysql.com/apt/ubuntu/ precise mysql-$MYSQL_VERSION
END

    apt-key adv --keyserver pool.sks-keyservers.net --recv-keys $MYSQ_GPG_KEY

    apt-get update
    apt-get install mysql-server

    dpkg -l|grep ^ii|grep mysql-server|grep ${MYSQL_VERSION/-dmr/}

else
    remove_mysql

    apt-get install python-software-properties

    apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
    add-apt-repository "deb http://nyc2.mirrors.digitalocean.com/mariadb/repo/$MARIA_VERSION/ubuntu precise main"

    apt-get update -qq

    apt-get install mariadb-server
fi

tee /etc/mysql/conf.d/map.cnf << END
[mysqld]
max_allowed_packet=$MAX_ALLOWED_PACKET
innodb_log_file_size=$INNODB_LOG_FILE_SIZE
END

# Generate SSL files:
./travis/gen-ssl.sh mariadb.example.com /etc/mysql
chown mysql:mysql /etc/mysql/server.crt /etc/mysql/server.key /etc/mysql/ca.crt

# Enable SSL:
tee /etc/mysql/conf.d/ssl.cnf << END
[mysqld]
ssl-ca=/etc/mysql/ca.crt
ssl-cert=/etc/mysql/server.crt
ssl-key=/etc/mysql/server.key
END

mysql -u root -e "SET GLOBAL innodb_fast_shutdown = 1"

service mysql stop
rm -f /var/lib/mysql/ib_logfile*
service mysql start

#Adding sleep time if mysql DB. If not SSL not totally initialized when launching tests
if [ "x$MYSQL_VERSION" != "x" ]
then
    sleep 20
fi

mysql -uroot -e "create database IF NOT EXISTS test"
