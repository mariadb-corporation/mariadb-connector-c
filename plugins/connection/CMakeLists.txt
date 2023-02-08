# Source-Replica Replication
REGISTER_PLUGIN(TARGET replication
                TYPE MARIADB_CLIENT_PLUGIN_CONNECTION
                CONFIGURATIONS STATIC DYNAMIC OFF
                DEFAULT OFF
                SOURCES ${CC_SOURCE_DIR}/plugins/connection/replication.c)
# Multi-source
REGISTER_PLUGIN(TARGET multisource
                TYPE MARIADB_CLIENT_PLUGIN_CONNECTION
                CONFIGURATIONS STATIC DYNAMIC OFF
                DEFAULT OFF
                SOURCES ${CC_SOURCE_DIR}/plugins/connection/multisource.c)
