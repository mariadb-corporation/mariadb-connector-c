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
#include <time.h>

static uint8_t binlog_disabled= 0;

static int test_binlog_available(MYSQL *mysql)
{
  int rc;
  MYSQL_RES *result;
  MYSQL_ROW row;

  if (mysql->server_capabilities & CLIENT_MYSQL)
    is_mariadb = 0;

  rc= mysql_query(mysql, "SELECT @@log_bin");
  check_mysql_rc(rc, mysql);

  result= mysql_store_result(mysql);
  row= mysql_fetch_row(result);
  if (!atoi(row[0]))
  {
    binlog_disabled= 1;
    diag("binlog disabled");
  }
  mysql_free_result(result);

  return OK;
}

static uint32_t get_binlog_position(MYSQL *mysql, char *filename)
{
  int rc;
  MYSQL_RES *result;
  MYSQL_ROW row;
  uint32_t pos= 0;

  if (is_mariadb)
    rc= mysql_query(mysql, "SHOW MASTER STATUS");
  else
    rc= mysql_query(mysql, "SHOW BINARY LOG STATUS");
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

//  if (!is_mariadb)
//    return SKIP;

  if (binlog_disabled)
  {
    diag("binary log disabled");
    return SKIP;
  }

  mysql = mysql_init(NULL);
  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1))
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

//  if (!is_mariadb)
//    return SKIP;

  if (binlog_disabled)
  {
    diag("binary log disabled");
    return SKIP;
  }

  mysql= mysql_init(NULL);
  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1))
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

//  if (!is_mariadb)
//    return SKIP;

  if (binlog_disabled)
  {
    diag("binary log disabled");
    return SKIP;
  }

  mysql= mysql_init(NULL);
  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1))
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
    else {
      diag("filename: %.*s", (int)rpl->filename_length, rpl->filename);
    }
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

//  if (!is_mariadb)
//    return SKIP;

  if (binlog_disabled)
  {
    diag("binary log disabled");
    return SKIP;
  }

  mysql= mysql_init(NULL);
  mysql_optionsv(mysql, MARIADB_OPT_RPL_REGISTER_REPLICA, host, 123);

  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  mysql_check= mysql_init(NULL);

  if (!my_test_connect(mysql_check, hostname, username,
                             password, schema, port, socketname, 0, 1))
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

  if (!is_mariadb)
    rc= mysql_query(mysql_check, "SHOW REPLICAS");
  else
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
  uint timeout_seconds=5;
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
  mysql_optionsv(mysql, MYSQL_OPT_READ_TIMEOUT, (void *)&timeout_seconds);
  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1))
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

static int test_gtid_event_parsing(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql;
  MARIADB_RPL_EVENT *event = NULL;
  MARIADB_RPL *rpl;
  char binlog_file[128];
  uint32_t binlog_pos;
  uint timeout_seconds = 5;
  uint32_t expected_domain = 887766; /* Identifiable test domain token */
  int rc;
  int ret = FAIL;
  char set_domain_query[64];

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (binlog_disabled)
  {
    diag("binary log disabled");
    return SKIP;
  }

  if (!is_mariadb)
    return SKIP;

  mysql = mysql_init(NULL);
  mysql_optionsv(mysql, MYSQL_OPT_READ_TIMEOUT, (void *)&timeout_seconds);
  if (!my_test_connect(mysql, hostname, username,
                       password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  /* 1. Force the active session configuration to yield deterministic properties */
  rc = mysql_query(mysql, "SET SESSION sql_log_bin = 1");
  check_mysql_rc(rc, mysql);

  snprintf(set_domain_query, sizeof(set_domain_query), "SET SESSION gtid_domain_id = %u", expected_domain);
  rc = mysql_query(mysql, set_domain_query);
  check_mysql_rc(rc, mysql);

  /* Establish positions right before generating the target event layout */
  binlog_pos = get_binlog_position(mysql, binlog_file);
  diag("Target testing binlog_file: %s at position: %u", binlog_file, binlog_pos);

  /* 2. Instantiate and configure our replication state metadata tracking system */
  rpl = mariadb_rpl_init(mysql);
  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");
  
  rpl->server_id = 99;
  rpl->start_position = 4;
  rpl->flags = MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  mariadb_rpl_optionsv(rpl, MARIADB_RPL_FILENAME, binlog_file, strlen(binlog_file));
  mariadb_rpl_optionsv(rpl, MARIADB_RPL_START, binlog_pos);

  /* 3. Execute a clear transactional DDL or statement to force immediate GTID generation */
  rc = mysql_query(mysql, "DROP TABLE IF EXISTS t_gtid_test");
  check_mysql_rc(rc, mysql);

  rc = mysql_query(mysql, "CREATE TABLE t_gtid_test (id INT)");
  check_mysql_rc(rc, mysql);

  /* 4. Open the streaming connection handle */
  if (mariadb_rpl_open(rpl))
  {
    mariadb_rpl_close(rpl);
    mysql_close(mysql);
    return FAIL;
  }

  /* 5. Process events until we catch our GTID structure */
  while ((event = mariadb_rpl_fetch(rpl, NULL)))
  {
    /* MariaDB GTID_EVENT identification signature */
    if (event->event_type == 162) /* GTID_EVENT */
    {
      /* Validate extracted bounds variables directly via your driver struct mappings */
      if (event->event.gtid.domain_id == expected_domain)
      {
        /* Ensure sequence identification has registered positively */
        if (event->event.gtid.sequence_nr > 0)
        {
          diag("Extracted GTID matched successfully! Seq: %llu, Domain: %u", 
               (unsigned long long)event->event.gtid.sequence_nr, 
               event->event.gtid.domain_id);
          ret = OK;
        }
        else
        {
          diag("Error: Captured GTID event but sequence_nr was 0 or invalid");
        }
      }
      else
      {
        diag("Encountered adjacent GTID context domain: %u (Waiting for %u)", 
             event->event.gtid.domain_id, expected_domain);
      }
      
      mariadb_free_rpl_event(event);
      event = NULL;
      
    }
    else
    {
      mariadb_free_rpl_event(event);
      event = NULL;
    }
  }

  if (event)
    mariadb_free_rpl_event(event);

  /* Cleanup tracking artifacts from target schema cleanly */
  mysql_query(mysql, "DROP TABLE IF EXISTS t_gtid_test");

  mariadb_rpl_close(rpl);
  mysql_close(mysql);
  return ret;
}

static int test_mariadb_all_specific_events(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql;
  MYSQL_RES *res;
  MYSQL_ROW row;
  MARIADB_RPL_EVENT *event= NULL;
  MARIADB_RPL *rpl;
  char binlog_file[128];
  uint32_t binlog_pos;
  uint timeout_seconds= 5;
  int rc;
  int ret = FAIL;

  /* State tracking to safely restore server variables after the test */
  char orig_log_bin_compress[16]= "OFF";
  char orig_log_bin_compress_min_len[16]= "256";

  /* Exhaustive tracking for all core and specific MariaDB variations */
  int seen_rotate= 0;
  int seen_annotate= 0;
  int seen_checkpoint= 0;
  int seen_gtid= 0;
  int seen_gtid_list= 0;
  
  /* Compression structural state tracking */
  int seen_start_compression= 0;
  int seen_compressed_write= 0;
  int seen_compressed_update= 0;
  int seen_compressed_delete= 0;

  /* Uncompressed standard state tracking */
  int seen_standard_write= 0;
  int seen_standard_update= 0;
  int seen_standard_delete= 0;

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
  mysql_optionsv(mysql, MYSQL_OPT_READ_TIMEOUT, (void *)&timeout_seconds);
  if (!my_test_connect(mysql, hostname, username,
                       password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  rc = mysql_query(mysql, "SET global binlog_format=ROW");
  check_mysql_rc(rc, mysql);
  rc = mysql_query(mysql, "SET session binlog_format=ROW");
  check_mysql_rc(rc, mysql);

  /* 1. Save original compression configuration states using standard API functions */
  rc= mysql_query(mysql, "SHOW GLOBAL VARIABLES LIKE 'log_bin_compress%'");
  check_mysql_rc(rc, mysql);
  
  if ((res = mysql_store_result(mysql))) {
    while ((row = mysql_fetch_row(res))) {
      if (row[0] && row[1]) {
        if (strcmp(row[0], "log_bin_compress") == 0)
          strncpy(orig_log_bin_compress, row[1], sizeof(orig_log_bin_compress) - 1);
        else if (strcmp(row[0], "log_bin_compress_min_len") == 0)
          strncpy(orig_log_bin_compress_min_len, row[1], sizeof(orig_log_bin_compress_min_len) - 1);
      }
    }
    mysql_free_result(res);
  }

  /* 2. Setup baseline environments and drop cleanup artifacts */
  rc= mysql_query(mysql, "SET GLOBAL binlog_annotate_row_events= 1");
  check_mysql_rc(rc, mysql);
  rc= mysql_query(mysql, "SET SESSION binlog_annotate_row_events= 1");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "DROP TABLE IF EXISTS t_mariadb_events");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "CREATE TABLE t_mariadb_events (a INT PRIMARY KEY, b VARCHAR(255)) ENGINE=InnoDB");
  check_mysql_rc(rc, mysql);

  /* 3. Flush to lock down a clean start boundary for the stream parser */
  rc= mysql_query(mysql, "FLUSH BINARY LOGS");
  check_mysql_rc(rc, mysql);

  binlog_pos= get_binlog_position(mysql, binlog_file);
  diag("Target starting binlog_file: %s at pos: %u", binlog_file, binlog_pos);

  /* =========================================================================
   * WORKLOAD BLOCK A: COMPRESSED EVENTS
   * ========================================================================= */
  rc= mysql_query(mysql, "SET GLOBAL log_bin_compress= 1");
  check_mysql_rc(rc, mysql);
  rc= mysql_query(mysql, "SET GLOBAL log_bin_compress_min_len= 10");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "START TRANSACTION");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "INSERT INTO t_mariadb_events VALUES (1, 'compression_test_string_payload_long_enough_to_trigger')");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "UPDATE t_mariadb_events SET b='altered_compression_test_string_payload_long_enough_to_trigger' WHERE a=1");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "DELETE FROM t_mariadb_events WHERE a=1");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "COMMIT");
  check_mysql_rc(rc, mysql);

  /* =========================================================================
   * WORKLOAD BLOCK B: UNCOMPRESSED STANDARD EVENTS
   * ========================================================================= */
  rc= mysql_query(mysql, "SET GLOBAL log_bin_compress= 0");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "START TRANSACTION");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "INSERT INTO t_mariadb_events VALUES (2, 'uncompressed_regular_flow_test')");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "UPDATE t_mariadb_events SET b='uncompressed_regular_flow_altered' WHERE a=2");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "DELETE FROM t_mariadb_events WHERE a=2");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "COMMIT");
  check_mysql_rc(rc, mysql);

  /* Force a checkpoint event explicitly in the binlog stream */
  rc= mysql_query(mysql, "FLUSH NO_WRITE_TO_BINLOG ENGINE LOGS");
  check_mysql_rc(rc, mysql);

  /* Final log rotation to sweep and push trailing headers (163/161) to the current loop */
  // rc= mysql_query(mysql, "FLUSH BINARY LOGS");
  // check_mysql_rc(rc, mysql);

  /* 4. Setup and open replication stream */
  rpl = mariadb_rpl_init(mysql);
  
  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");
  
  rpl->server_id= 14;
  rpl->start_position= 4;
  rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  mariadb_rpl_optionsv(rpl, MARIADB_RPL_FILENAME, binlog_file, strlen(binlog_file));
  mariadb_rpl_optionsv(rpl, MARIADB_RPL_START, 4);

  if (mariadb_rpl_open(rpl))
  {
    diag("Error: Failed to open replication stream");
    mariadb_rpl_close(rpl);
    mysql_close(mysql);
    return FAIL;
  }

  /* 5. Iterate through the replication log sequence */
  while((event= mariadb_rpl_fetch(rpl, NULL)))
  {
    diag("Fetched Event Type ID: %d from binlog-file: %.*s", event->event_type, rpl->filename_length, rpl->filename);

    switch(event->event_type)
    {
      case ROTATE_EVENT:
        seen_rotate= 1;
        break;
      case ANNOTATE_ROWS_EVENT:
        seen_annotate= 1;
        break;
      case BINLOG_CHECKPOINT_EVENT:
        seen_checkpoint= 1;
        break;
      case GTID_EVENT:
        seen_gtid= 1;
        break;
      case GTID_LIST_EVENT:
        seen_gtid_list= 1;
        break;

      /* Compressed variants */
      case QUERY_COMPRESSED_EVENT:
        seen_start_compression= 1;
        break;
      case WRITE_ROWS_COMPRESSED_EVENT_V1:
        seen_compressed_write= 1;
        break;
      case UPDATE_ROWS_COMPRESSED_EVENT_V1:
        seen_compressed_update= 1;
        break;
      case DELETE_ROWS_COMPRESSED_EVENT_V1:
        seen_compressed_delete= 1;
        break;

      /* Standard uncompressed variants */
      case WRITE_ROWS_EVENT_V1:
      case WRITE_ROWS_EVENT:
        seen_standard_write= 1;
        break;
      case UPDATE_ROWS_EVENT_V1:
      case UPDATE_ROWS_EVENT:
        seen_standard_update= 1;
        break;
      case DELETE_ROWS_EVENT_V1:
      case DELETE_ROWS_EVENT:
        seen_standard_delete= 1;
        break;

      default:
        break;
    }
    if (mariadb_rpl_errno(rpl))
      diag("Error: >%s<", mariadb_rpl_error(rpl));
    mariadb_free_rpl_event(event);
    event = NULL;

    /* Break early once absolutely every structural footprint has been satisfied */
    if (seen_rotate && seen_annotate && seen_checkpoint && seen_gtid && seen_gtid_list &&
        seen_start_compression && seen_compressed_write && seen_compressed_update && seen_compressed_delete &&
        seen_standard_write && seen_standard_update && seen_standard_delete) {
      ret = OK;
      goto end;
    }
  }

end:
  if (event)
    mariadb_free_rpl_event(event);

  {
    int compression_validated = (seen_compressed_write && seen_compressed_update && seen_compressed_delete) || seen_start_compression;
    int standard_validated = (seen_standard_write && seen_standard_update && seen_standard_delete);
    char restore_cmd[128];

    if (seen_annotate && seen_checkpoint && seen_gtid && seen_gtid_list && 
        compression_validated && standard_validated) {
      ret = OK;
    } else {
      diag("Test Failed! Missing structural footprints:");
      if (!compression_validated)   diag(" -> Missing: Compressed Row Variants");
      if (!seen_standard_write)     diag(" -> Missing: STANDARD_WRITE");
      if (!seen_standard_update)    diag(" -> Missing: STANDARD_UPDATE");
      if (!seen_standard_delete)    diag(" -> Missing: STANDARD_DELETE");
      if (!seen_annotate)           diag(" -> Missing: ANNOTATE_ROWS_EVENT");
      if (!seen_checkpoint)         diag(" -> Missing: BINLOG_CHECKPOINT_EVENT");
      if (!seen_gtid_list)          diag(" -> Missing: GTID_LIST_EVENT");
      ret = FAIL;
    }

    /* 7. Clean up tables and restore engine server variables to original configurations */
    mysql_query(mysql, "DROP TABLE IF EXISTS t_mariadb_events");
    
    snprintf(restore_cmd, sizeof(restore_cmd), "SET GLOBAL log_bin_compress= %s", orig_log_bin_compress);
    mysql_query(mysql, restore_cmd);
    snprintf(restore_cmd, sizeof(restore_cmd), "SET GLOBAL log_bin_compress_min_len= %s", orig_log_bin_compress_min_len);
    mysql_query(mysql, restore_cmd);

    mariadb_rpl_close(rpl);
    mysql_close(mysql);
  }
  return ret;
}

static int test_mariadb_event_contents(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql;
  MYSQL_RES *res;
  MYSQL_ROW row;
  MARIADB_RPL_EVENT *event= NULL;
  MARIADB_RPL_EVENT *table_map_event= NULL; /* Kept to decode row images */
  MARIADB_RPL *rpl;
  char binlog_file[128];
  uint32_t binlog_pos;
  uint timeout_seconds= 5;
  int rc;
  int ret = FAIL;

  /* State tracking to safely restore server variables after the test */
  char orig_log_bin_compress[16]= "OFF";
  char orig_log_bin_compress_min_len[16]= "256";

  /* Exhaustive tracking for all core and specific MariaDB variations */
  int seen_rotate= 0;
  int seen_annotate= 0;
  int seen_checkpoint= 0;
  int seen_gtid= 0;
  int seen_gtid_list= 0;

  /* Compression structural state tracking */
  int seen_start_compression= 0;
  int seen_compressed_write= 0;
  int seen_compressed_update= 0;
  int seen_compressed_delete= 0;

  /* Uncompressed standard state tracking */
  int seen_standard_write= 0;
  int seen_standard_update= 0;
  int seen_standard_delete= 0;

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
  mysql_optionsv(mysql, MYSQL_OPT_READ_TIMEOUT, (void *)&timeout_seconds);
  if (!my_test_connect(mysql, hostname, username,
                       password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  /* 1. Save original compression configuration states */
  rc= mysql_query(mysql, "SHOW GLOBAL VARIABLES LIKE 'log_bin_compress%'");
  check_mysql_rc(rc, mysql);
  
  if ((res = mysql_store_result(mysql))) {
    while ((row = mysql_fetch_row(res))) {
      if (row[0] && row[1]) {
        if (strcmp(row[0], "log_bin_compress") == 0)
          strncpy(orig_log_bin_compress, row[1], sizeof(orig_log_bin_compress) - 1);
        else if (strcmp(row[0], "log_bin_compress_min_len") == 0)
          strncpy(orig_log_bin_compress_min_len, row[1], sizeof(orig_log_bin_compress_min_len) - 1);
      }
    }
    mysql_free_result(res);
  }

  /* 2. Setup baseline environments and drop cleanup artifacts */
  rc= mysql_query(mysql, "SET GLOBAL binlog_annotate_row_events= 1");
  check_mysql_rc(rc, mysql);
  rc= mysql_query(mysql, "SET SESSION binlog_annotate_row_events= 1");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "DROP TABLE IF EXISTS t_mariadb_events");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "CREATE TABLE t_mariadb_events (a INT PRIMARY KEY, b VARCHAR(255)) ENGINE=InnoDB");
  check_mysql_rc(rc, mysql);

  /* 3. Flush to lock down a clean start boundary for the stream parser */
  rc= mysql_query(mysql, "FLUSH BINARY LOGS");
  check_mysql_rc(rc, mysql);

  binlog_pos= get_binlog_position(mysql, binlog_file);
  diag("Target starting binlog_file: %s at pos: %u", binlog_file, binlog_pos);

  /* =========================================================================
   * WORKLOAD BLOCK A: COMPRESSED EVENTS
   * ========================================================================= */
  rc= mysql_query(mysql, "SET GLOBAL log_bin_compress= 1");
  check_mysql_rc(rc, mysql);
  rc= mysql_query(mysql, "SET GLOBAL log_bin_compress_min_len= 10");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "START TRANSACTION");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "INSERT INTO t_mariadb_events VALUES (1, 'compression_test_string_payload_long_enough_to_trigger')");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "UPDATE t_mariadb_events SET b='altered_compression_test_string_payload_long_enough_to_trigger' WHERE a=1");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "DELETE FROM t_mariadb_events WHERE a=1");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "COMMIT");
  check_mysql_rc(rc, mysql);

  /* =========================================================================
   * WORKLOAD BLOCK B: UNCOMPRESSED STANDARD EVENTS
   * ========================================================================= */
  rc= mysql_query(mysql, "SET GLOBAL log_bin_compress= 0");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "START TRANSACTION");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "INSERT INTO t_mariadb_events VALUES (2, 'uncompressed_regular_flow_test')");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "UPDATE t_mariadb_events SET b='uncompressed_regular_flow_altered' WHERE a=2");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "DELETE FROM t_mariadb_events WHERE a=2");
  check_mysql_rc(rc, mysql);
  
  rc= mysql_query(mysql, "COMMIT");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "FLUSH NO_WRITE_TO_BINLOG ENGINE LOGS");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "FLUSH BINARY LOGS");
  check_mysql_rc(rc, mysql);

  /* 4. Setup and open replication stream */
  rpl = mariadb_rpl_init(mysql);
  
  mysql_query(mysql, "SET @mariadb_slave_capability=4");
  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");

  binlog_pos= 4;

  rpl->server_id= 15;
  rpl->start_position= binlog_pos;
  rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

  mariadb_rpl_optionsv(rpl, MARIADB_RPL_FILENAME, binlog_file, strlen(binlog_file));
  mariadb_rpl_optionsv(rpl, MARIADB_RPL_START, binlog_pos);

  if (mariadb_rpl_open(rpl))
  {
    diag("Error: Failed to open replication stream");
    mariadb_rpl_close(rpl);
    mysql_close(mysql);
    return FAIL;
  }

  /* 5. Iterate through the replication log sequence and validate content */
  while((event= mariadb_rpl_fetch(rpl, NULL)))
  {
    diag("Fetched Event Type ID: %d", event->event_type);

    switch(event->event_type)
    {
      case ROTATE_EVENT:
        seen_rotate= 1;
        (void)seen_rotate;
        /* CONTENT CHECK: Length-bounded memory matching for safety */
        if (event->event.rotate.filename.length > 0 && event->event.rotate.filename.str != NULL) {
          size_t flen = event->event.rotate.filename.length;

          if (flen > 1024) {
            diag("Content Error: ROTATE_EVENT filename length is impossibly large: %zu", flen);
            goto end;
          }

        } else {
          diag("Content Error: ROTATE_EVENT contains zero length or null string context");
          goto end;
        }
        break;

      case FORMAT_DESCRIPTION_EVENT:
        if (event->event.format_description.server_version == NULL ||
            strlen(event->event.format_description.server_version) == 0) {
          diag("Content Error: Empty server version string inside FORMAT_DESCRIPTION_EVENT");
          goto end;
        }
        break;

      case TABLE_MAP_EVENT:
      {
        const char *expected_table = "t_mariadb_events";
        size_t expected_len = strlen(expected_table);

        if (table_map_event)
          mariadb_free_rpl_event(table_map_event);
        table_map_event = event;
        
        /* CONTENT CHECK: Match string using explicit length tracking boundaries */
        
        if (table_map_event->event.table_map.table.length != expected_len || 
            memcmp(table_map_event->event.table_map.table.str, expected_table, expected_len) != 0) {
          diag("Content Error: TABLE_MAP_EVENT mapped to incorrect table name bounds");
          goto end;
        }
        continue; /* Skip freeing because we retained it */
      }

      case ANNOTATE_ROWS_EVENT:
        seen_annotate= 1;
        /* CONTENT CHECK: Ensure statement tracking structural lengths are populated */
        if (event->event.annotate_rows.statement.length == 0 || 
            event->event.annotate_rows.statement.str == NULL) {
          diag("Content Error: ANNOTATE_ROWS_EVENT missing tracked structural query payload bounds");
          goto end;
        }
        break;

      case BINLOG_CHECKPOINT_EVENT:
        seen_checkpoint= 1;
        break;

      case GTID_EVENT:
        seen_gtid= 1;
        if (event->event.gtid.sequence_nr == 0) {
          diag("Content Error: Invalid GTID structural seq_no value assigned");
          goto end;
        }
        break;

      case GTID_LIST_EVENT:
        seen_gtid_list= 1;
        break;

      case QUERY_COMPRESSED_EVENT:
        seen_start_compression= 1;
        break;

      /* Compressed and Standard Row Extraction Logic Validation */
      case WRITE_ROWS_EVENT_V1:
      case WRITE_ROWS_EVENT:
      case WRITE_ROWS_COMPRESSED_EVENT_V1:
      {
        int64_t checked_id;
        if (event->event_type == WRITE_ROWS_COMPRESSED_EVENT_V1) seen_compressed_write = 1;
        else seen_standard_write = 1;

        if (table_map_event) {
          MARIADB_RPL_ROW *rpl_row = mariadb_rpl_extract_rows(rpl, table_map_event, event);
          if (!rpl_row) {
            diag("Content Error: Failed to extract row information from write event context");
            goto end;
          }
          checked_id = rpl_row->columns[0].val.ll; 
          if (checked_id != 1 && checked_id != 2) {
            diag("Content Error: Unpacked row ID mapping returned unexpected integer layout: %lld", (long long)checked_id);
            goto end;
          }
        }
        break;
      }

      case UPDATE_ROWS_EVENT_V1:
      case UPDATE_ROWS_EVENT:
      case UPDATE_ROWS_COMPRESSED_EVENT_V1:
        if (event->event_type == UPDATE_ROWS_COMPRESSED_EVENT_V1) seen_compressed_update = 1;
        else seen_standard_update = 1;
        break;

      case DELETE_ROWS_EVENT_V1:
      case DELETE_ROWS_EVENT:
      case DELETE_ROWS_COMPRESSED_EVENT_V1:
        if (event->event_type == DELETE_ROWS_COMPRESSED_EVENT_V1) seen_compressed_delete = 1;
        else seen_standard_delete = 1;
        break;

      default:
        break;
    }

    mariadb_free_rpl_event(event);
    event = NULL;
  }

end:
  if (event)
    mariadb_free_rpl_event(event);
  if (table_map_event)
    mariadb_free_rpl_event(table_map_event);

  /* 6. Verify comprehensive metric validation status */
  {
    int compression_validated = (seen_compressed_write && seen_compressed_update && seen_compressed_delete) || seen_start_compression;
    int standard_validated = (seen_standard_write && seen_standard_update && seen_standard_delete);
    char restore_cmd[128];

    if (seen_annotate && seen_checkpoint && seen_gtid && seen_gtid_list && 
        compression_validated && standard_validated) {
      ret = OK;
    } else {
      diag("Test Failed! Missing structural footprints.");
      ret = FAIL;
    }

  /* 7. Clean up tables and restore configurations */
    mysql_query(mysql, "DROP TABLE IF EXISTS t_mariadb_events");
  
    snprintf(restore_cmd, sizeof(restore_cmd), "SET GLOBAL log_bin_compress= %s", orig_log_bin_compress);
    mysql_query(mysql, restore_cmd);
    snprintf(restore_cmd, sizeof(restore_cmd), "SET GLOBAL log_bin_compress_min_len= %s", orig_log_bin_compress_min_len);
    mysql_query(mysql, restore_cmd);
  }

  mariadb_rpl_close(rpl);
  mysql_close(mysql);
  return ret;
}

static int test_mariadb_heartbeat_event(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql;
  MARIADB_RPL_EVENT *event= NULL;
  MARIADB_RPL *rpl;
  char binlog_file[128];
  uint32_t binlog_pos;
  uint timeout_seconds= 5; /* Keep read timeout snappy for polling */
  int rc;
  int ret = FAIL;
  time_t start_time;

  /* State tracking variables */
  int seen_heartbeat= 0;

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
  mysql_optionsv(mysql, MYSQL_OPT_READ_TIMEOUT, (void *)&timeout_seconds);
  if (!my_test_connect(mysql, hostname, username,
                       password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  mysql_query(mysql, "SET @master_binlog_checksum= @@global.binlog_checksum");

  /* 
   * STEP 1: Initialize replication session parameters.
   * We set both nanosecond and second variations to guarantee compatibility 
   * across different MariaDB server versions, matching the registration sequence.
   */
  rc= mysql_query(mysql, "SET @master_heartbeat_period= 1000000000"); /* 1s in ns */
  if (!rc) {
    rc= mysql_query(mysql, "SET @mariadb_slave_capability= 4");
  }
  
  /* Fallback check: ensure a secondary 1-second representation is attempted */
  mysql_query(mysql, "SET @master_heartbeat_period= 1.000"); 

  if (rc)
  {
    diag("Error initializing heartbeat session parameters: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  /* Capture current binary log position coordinates */
  binlog_pos= get_binlog_position(mysql, binlog_file);
  diag("Heartbeat targeting binlog_file: %s at pos: %u", binlog_file, binlog_pos);

  /* Instantiate and configure replication context */
  rpl = mariadb_rpl_init(mysql);
  if (!rpl)
  {
    diag("Error: Failed to initialize MARIADB_RPL");
    mysql_close(mysql);
    return FAIL;
  }

  rpl->server_id= 16;
  rpl->start_position= binlog_pos;
  rpl->flags= 0; 

  mariadb_rpl_optionsv(rpl, MARIADB_RPL_FILENAME, binlog_file, strlen(binlog_file));
  mariadb_rpl_optionsv(rpl, MARIADB_RPL_START, binlog_pos);

  /* STEP 2: Establish the replication stream channel */
  if (mariadb_rpl_open(rpl))
  {
    diag("Error: Failed to open replication stream");
    mariadb_rpl_close(rpl);
    mysql_close(mysql);
    return FAIL;
  }

  diag("Replication stream established. Waiting for a heartbeat...");

  /* 
   * STEP 3: Wall-clock time-bounded loop.
   * The window must comfortably exceed the network read timeout value (5s) 
   * to guarantee that at least one full blocking lifecycle executes completely.
   */
  start_time = time(NULL);
  while ((time(NULL) - start_time) < 12 && !seen_heartbeat)
  {
    event= mariadb_rpl_fetch(rpl, NULL);
    if (!event)
    {
      /* Check if the stream encountered a terminal database network error */
      if (mysql_errno(mysql) != 0)
      {
        diag("Stream broken with MySQL Error: %s", mysql_error(mysql));
        break;
      }
      continue;
    }

    diag("Fetched Event Type ID: %d", event->event_type);

    /* HEARTBEAT_LOG_EVENT is defined as 27 (0x1b) */
    if (event->event_type == 27)
    {
      seen_heartbeat= 1;
      diag("Success: Received valid HEARTBEAT_LOG_EVENT footprint");
    }

    mariadb_free_rpl_event(event);
    event = NULL;
  }

  if (seen_heartbeat)
  {
    ret = OK;
  }
  else
  {
    diag("Test Failed! Did not intercept HEARTBEAT_LOG_EVENT within the execution window.");
    ret = FAIL;
  }

  mariadb_rpl_close(rpl);
  mysql_close(mysql);
  return ret;
}

struct my_tests_st my_tests[] = {
  /* His test needs to be run first */
  {"test_binlog_available", test_binlog_available, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_heartbeat", test_mariadb_heartbeat_event, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_mariadb_all_specific_events", test_mariadb_all_specific_events, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_mariadb_event_contents", test_mariadb_event_contents, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_gtid_event_parsing", test_gtid_event_parsing, TEST_CONNECTION_NONE, 0, NULL, NULL},
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
