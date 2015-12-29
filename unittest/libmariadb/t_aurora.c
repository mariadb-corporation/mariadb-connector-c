/*
*/

#include "my_test.h"

static int aurora1(MYSQL *mysql)
{
  int rc;
  my_bool read_only= 1;
  char *primary, *replica;
  MYSQL_RES *res;

  rc= mysql_query(mysql, "DROP TABLE IF EXISTS t1");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "CREATE TABLE t1 (a int, b varchar(20))");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "INSERT INTO t1 VALUES (1, 'foo'), (2, 'bar')");
  check_mysql_rc(rc, mysql);

  primary= mysql->host;
  diag("primary: %s", primary);

  mysql_options(mysql, MARIADB_OPT_CONNECTION_READ_ONLY, &read_only);

  /* ensure, that this is a replica, so INSERT should fail */
  rc= mysql_query(mysql, "INSERT INTO t1 VALUES (3, 'error')");
  if (rc)
    diag("Expected error: %s", mysql_error(mysql));

  rc= mysql_query(mysql, "SELECT a, b FROM t1");
  check_mysql_rc(rc, mysql);

  res= mysql_store_result(mysql);

  diag("Num_rows: %d", mysql_num_rows(res));
  mysql_free_result(res);

  replica= mysql->host;
  diag("replica: %s", replica);
  diag("db: %s", mysql->db);

  return OK;
}

struct my_tests_st my_tests[] = {
  {"aurora1", aurora1, TEST_CONNECTION_NEW, 0,  NULL,  NULL},
  {NULL, NULL, 0, 0, NULL, NULL}
};


int main(int argc, char **argv)
{

  mysql_library_init(0,0,NULL);

  if (argc > 1)
    get_options(argc, argv);

  get_envvars();

  run_tests(my_tests);

  mysql_server_end();
  return(exit_status());
}
