/*
Copyright (c) 2016 MariaDB Corporation AB

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
#include "ma_common.h"

void show_time(struct timeval t1)
{
  struct timeval t2;
  double elapsed;
  gettimeofday(&t2, NULL);
  elapsed = ((t2.tv_sec - t1.tv_sec)* 1000.0 + (t2.tv_usec - t1.tv_usec) / 1000.0) / 1000;
  diag("elapsed: %5.2f", elapsed);
}

static int perf1(MYSQL *mysql)
{
  int rc;
  MYSQL_STMT *stmt;
  struct timeval t1;
  char *stmtstr= "SELECT s.emp_no, s.salary, e.emp_no, e.first_name, e.last_name, e.gender FROM salaries s, employees e WHERE s.emp_no = e.emp_no";

  rc= mysql_select_db(mysql, "employees");
  if (rc)
  {
    diag("Employees database not installed");
    return SKIP;
  }

  stmt= mysql_stmt_init(mysql);

  diag("prepare");
  gettimeofday(&t1, NULL);
  rc= mysql_stmt_prepare(stmt, stmtstr, strlen(stmtstr));
  check_stmt_rc(rc, stmt);
  show_time(t1);

  diag("execute");
  gettimeofday(&t1, NULL);
  rc= mysql_stmt_execute(stmt);
  check_stmt_rc(rc, stmt);
  show_time(t1);

  diag("store");
  gettimeofday(&t1, NULL);
  rc= mysql_stmt_store_result(stmt);
  check_stmt_rc(rc, stmt);
  show_time(t1);

  diag("fetch");
  gettimeofday(&t1, NULL);
  while (!mysql_stmt_fetch(stmt));
  show_time(t1);

  mysql_stmt_close(stmt);
  return OK;
}

struct my_tests_st my_tests[] = {
  {"perf1", perf1, TEST_CONNECTION_NEW, 0,  NULL,  NULL},
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
