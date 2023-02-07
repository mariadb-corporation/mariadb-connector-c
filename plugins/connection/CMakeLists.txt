# Master-Slave Replication
REGISTER_PLUGIN(TARGET replication
                TYPE MARIADB_CLIENT_PLUGIN_CONNECTION
                CONFIGURATIONS STATIC DYNAMIC OFF
                DEFAULT OFF
                SOURCES ${CC_SOURCE_DIR}/plugins/connection/replication.c)
# Multi-master
REGISTER_PLUGIN(TARGET multimaster
                TYPE MARIADB_CLIENT_PLUGIN_CONNECTION
                CONFIGURATIONS STATIC DYNAMIC OFF
                DEFAULT OFF
                SOURCES ${CC_SOURCE_DIR}/plugins/connection/multimaster.c)
