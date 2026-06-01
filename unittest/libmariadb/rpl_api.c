/*
Copyright (c) 2018 MariaDB Corporation AB

The MySQL Connector/C is licensed under the terms of the GPLv2
<http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>, like most
MySQL Connectors. There are special exceptions to the terms and
conditions of the GPLv2 as it is applied to this software, see the
FLOSS License Exception
<http://www.mysql.com/about/legal/licensing/foss-exception.html>.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published
by the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/
/**
  Some basic tests of the client API.
*/

#include "my_test.h"
#include "mariadb_rpl.h"

static uint8_t binlog_disabled= 0;

static int test_binlog_available(MYSQL *mysql)
{
  int rc;
  MYSQL_RES *result;
  MYSQL_ROW row;

  rc= mysql_query(mysql, "SELECT @@log_bin");
  check_mysql_rc(rc, mysql);

  result= mysql_store_result(mysql);
  row= mysql_fetch_row(result);
  if (!atoi(row[0]))
    binlog_disabled= 1;
  mysql_free_result(result);

  return OK;
}

static uint32_t get_binlog_position(MYSQL *mysql, char *filename)
{
  int rc;
  MYSQL_RES *result;
  MYSQL_ROW row;
  uint32_t pos= 0;


  rc= mysql_query(mysql, "SHOW MASTER STATUS");
  check_mysql_rc(rc, mysql);

  result= mysql_store_result(mysql);
  row= mysql_fetch_row(result);
  strcpy(filename, row[0]);
  pos= atoi(row[1]);
  mysql_free_result(result);

  return pos;
}

static int test_rpl_async(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql;
  MARIADB_RPL_EVENT *event= NULL;
  MARIADB_RPL *rpl;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  if (binlog_disabled)
  {
    diag("binary log disabled");
    return SKIP;
  }

  mysql = mysql_init(NULL);
  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  rpl = mariadb_rpl_init(mysql);

  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET NAMES latin1");
  mysql_query(mysql, "SET @slave_gtid_strict_mode=1");
  mysql_query(mysql, "SET @slave_gtid_ignore_duplicates=1");
  mysql_query(mysql, "SET NAMES utf8");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");
  rpl->server_id= 12;
  rpl->start_position= 4;
  rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  if (mariadb_rpl_open(rpl))
    return FAIL;

  event= mariadb_rpl_fetch(rpl, NULL);
  mariadb_free_rpl_event(event);
  mariadb_rpl_close(rpl);
  mysql_close(mysql);
  return OK;
}

static int test_rpl_semisync(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql;
  MARIADB_RPL_EVENT *event= NULL;
  MARIADB_RPL *rpl;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  if (binlog_disabled)
  {
    diag("binary log disabled");
    return SKIP;
  }

  mysql= mysql_init(NULL);
  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  rpl = mariadb_rpl_init(mysql);

  mariadb_rpl_optionsv(rpl, MARIADB_RPL_HOST, "foo");

  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET NAMES latin1");
  mysql_query(mysql, "SET @slave_gtid_strict_mode=1");
  mysql_query(mysql, "SET @slave_gtid_ignore_duplicates=1");
  mysql_query(mysql, "SET NAMES utf8");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");
  rpl->server_id= 12;
  rpl->start_position= 4;
  rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET NAMES latin1");
  mysql_query(mysql, "SET @slave_gtid_strict_mode=1");
  mysql_query(mysql, "SET @slave_gtid_ignore_duplicates=1");
  mysql_query(mysql, "SET NAMES utf8");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");
  rpl->server_id= 12;
  rpl->start_position= 4;
  rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  if (mariadb_rpl_open(rpl))
    return FAIL;

  event= mariadb_rpl_fetch(rpl, event);

  mariadb_free_rpl_event(event);
  mariadb_rpl_close(rpl);
  mysql_close(mysql);
  return OK;
}

static int test_conc467(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql;
  MARIADB_RPL_EVENT *event= NULL;
  MARIADB_RPL *rpl;
  int rc;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  if (binlog_disabled)
  {
    diag("binary log disabled");
    return SKIP;
  }

  mysql= mysql_init(NULL);
  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  /* Force to create a log rotate event */
  rc= mysql_query(mysql, "FLUSH logs");
  check_mysql_rc(rc, mysql);

  rpl = mariadb_rpl_init(mysql);

  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET NAMES latin1");
  mysql_query(mysql, "SET @slave_gtid_strict_mode=1");
  mysql_query(mysql, "SET @slave_gtid_ignore_duplicates=1");
  mysql_query(mysql, "SET NAMES utf8");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");
  rpl->server_id= 12;
  rpl->start_position= 4;
  rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  if (mariadb_rpl_open(rpl))
    return FAIL;

  if (!(event= mariadb_rpl_fetch(rpl, event)))
    rc= FAIL;
  else
  {
    if (!rpl->filename)
    {
      diag("error: filename not set");
      rc= FAIL;
    }
    else
      diag("filename: %.*s", (int)rpl->filename_length, rpl->filename);
  }

  mariadb_free_rpl_event(event);
  mariadb_rpl_close(rpl);
  mysql_close(mysql);
  return rc;
}

static int test_conc592(MYSQL *my __attribute__((unused)))
{
  MARIADB_RPL *rpl;
  MYSQL *mysql, *mysql_check;
  const char *host= "myhost";
  MYSQL_RES *result;
  MYSQL_ROW row;
  int rc;
  int found= 0;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  if (binlog_disabled)
  {
    diag("binary log disabled");
    return SKIP;
  }

  mysql= mysql_init(NULL);
  mysql_optionsv(mysql, MARIADB_OPT_RPL_REGISTER_REPLICA, host, 123);

  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  mysql_check= mysql_init(NULL);

  if (!my_test_connect(mysql_check, hostname, username,
                             password, schema, port, socketname, 0))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  rpl = mariadb_rpl_init(mysql);

  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET NAMES latin1");
  mysql_query(mysql, "SET @slave_gtid_strict_mode=1");
  mysql_query(mysql, "SET @slave_gtid_ignore_duplicates=1");
  mysql_query(mysql, "SET NAMES utf8");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");
  mysql_query(mysql, "SET @rpl_semi_sync_slave=1");
  rpl->server_id= 12;
  rpl->start_position= 4;
  rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  if (mariadb_rpl_open(rpl))
    return FAIL;

  rc= mysql_query(mysql_check, "SHOW SLAVE HOSTS");
  check_mysql_rc(rc, mysql_check);

  result= mysql_store_result(mysql_check);

  while ((row= mysql_fetch_row(result)))
    if (!strcmp(row[1], host))
      found= 1;

  mysql_free_result(result);
  mariadb_rpl_close(rpl);
  mysql_close(mysql);
  mysql_close(mysql_check);

  if (!found)
  {
    diag("Host '%s' not found in replica list", host);
    return FAIL;
  }

  return OK;
}

static int test_conc815(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql;
  MYSQL_RES *result;
  MYSQL_ROW row;
  MARIADB_RPL_EVENT *event= NULL,
                    *table_map_event= NULL;
  MARIADB_RPL *rpl;
  MARIADB_TIMESTAMP ts[2] = {0};
  char binlog_file[128];
  uint32_t binlog_pos;
  int rc;
  int ret = FAIL;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  if (binlog_disabled)
  {
    diag("binary log disabled");
    return SKIP;
  }

  mysql= mysql_init(NULL);
  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  rpl = mariadb_rpl_init(mysql);

  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET NAMES latin1");
  mysql_query(mysql, "SET @slave_gtid_strict_mode=1");
  mysql_query(mysql, "SET @slave_gtid_ignore_duplicates=1");
  mysql_query(mysql, "SET NAMES utf8");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");
  rpl->server_id= 12;
  rpl->start_position= 4;
  rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  binlog_pos= get_binlog_position(mysql, binlog_file);
  diag("binlog_file: %s", binlog_file);

  mariadb_rpl_optionsv(rpl, MARIADB_RPL_FILENAME, binlog_file, strlen(binlog_file));
  mariadb_rpl_optionsv(rpl, MARIADB_RPL_START, binlog_pos);

  rc= mysql_query(mysql, "DROP TABLE IF EXISTS t1");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "CREATE TABLE t1 (a timestamp, b timestamp(6))");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "INSERT INTO t1 VALUES(now(), now(6))");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "SELECT unix_timestamp(a), FLOOR(UNIX_TIMESTAMP(b)) AS seconds, CAST((UNIX_TIMESTAMP(b) % 1) * 1000000 AS UNSIGNED) AS second_part FROM t1");
  if ((result = mysql_store_result(mysql))) {
    row= mysql_fetch_row(result);
    ts[0].second= atoi(row[0]);
    ts[1].second= atoi(row[1]);
    ts[1].second_part = atoi(row[2]);
    mysql_free_result(result);
  }

  if (mariadb_rpl_open(rpl))
    return FAIL;

  /* process all events */
  while((event= mariadb_rpl_fetch(rpl, NULL)))
  {
    if (event->event_type == TABLE_MAP_EVENT) {
      if (table_map_event)
        mariadb_free_rpl_event(table_map_event);
      table_map_event= event;
      continue;
    }

    if (event->event_type == WRITE_ROWS_EVENT_V1) {
      if (table_map_event) {
        MARIADB_RPL_ROW *rpl_row;

        if (!(rpl_row= mariadb_rpl_extract_rows(rpl, table_map_event, event))) {
          goto end;
        }
        if (rpl_row->columns[0].val.ts.second == ts[0].second &&
            rpl_row->columns[0].val.ts.second_part == 0 &&
            rpl_row->columns[1].val.ts.second == ts[1].second &&
            rpl_row->columns[1].val.ts.second_part == ts[1].second_part) {
          ret= OK;
        } else {
          diag("Error: Wrong timestamp values");
        }
        goto end;
      }
      goto end;
    } else {
      mariadb_free_rpl_event(event);
      event = NULL;
    }
  }
  ret = OK;
end:
  if (event)
    mariadb_free_rpl_event(event);
  if (table_map_event)
    mariadb_free_rpl_event(table_map_event);
  mariadb_rpl_close(rpl);
  mysql_close(mysql);
  return ret;
}

struct my_tests_st my_tests[] = {
  /* His test needs to be run first */
  {"test_binlog_available", test_binlog_available, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},

  {"test_rpl_async", test_rpl_async, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_rpl_semisync", test_rpl_semisync, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_conc815", test_conc815, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_conc592", test_conc592, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_conc467", test_conc467, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {NULL, NULL, 0, 0, NULL, NULL}
};


int main(int argc, char **argv)
{
  if (argc > 1)
    get_options(argc, argv);

  get_envvars();

  run_tests(my_tests);

  return(exit_status());
}
