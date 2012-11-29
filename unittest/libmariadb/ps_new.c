/************************************************************************************
  Copyright (C) 2012 Monty Program AB

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public
  License along with this library; if not see <http://www.gnu.org/licenses>
  or write to the Free Software Foundation, Inc.,
  51 Franklin St., Fifth Floor, Boston, MA 02110, USA
 *************************************************************************************/

#include "my_test.h"

/* Utility function to verify the field members */


static int test_multi_result(MYSQL *mysql)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND ps_params[3];  /* input parameter buffers */
  MYSQL_BIND rs_bind[3];
  int        int_data[3];   /* input/output values */
  my_bool    is_null[3];    /* output value nullability */
  int        rc, i;

  /* set up stored procedure */
  rc = mysql_query(mysql, "DROP PROCEDURE IF EXISTS p1");
  check_mysql_rc(rc, mysql);

  rc = mysql_query(mysql,
      "CREATE PROCEDURE p1("
      "  IN p_in INT, "
      "  OUT p_out INT, "
      "  INOUT p_inout INT) "
      "BEGIN "
      "  SELECT p_in, p_out, p_inout; "
      "  SET p_in = 100, p_out = 200, p_inout = 300; "
      "  SELECT p_in, p_out, p_inout; "
      "END");
  check_mysql_rc(rc, mysql);

  /* initialize and prepare CALL statement with parameter placeholders */
  stmt = mysql_stmt_init(mysql);
  if (!stmt)
  {
    printf("Could not initialize statement\n");
    exit(1);
  }
  rc = mysql_stmt_prepare(stmt, "CALL p1(?, ?, ?)", 16);
  check_stmt_rc(rc, stmt);

  /* initialize parameters: p_in, p_out, p_inout (all INT) */
  memset(ps_params, 0, sizeof (ps_params));

  ps_params[0].buffer_type = MYSQL_TYPE_LONG;
  ps_params[0].buffer = (char *) &int_data[0];
  ps_params[0].length = 0;
  ps_params[0].is_null = 0;

  ps_params[1].buffer_type = MYSQL_TYPE_LONG;
  ps_params[1].buffer = (char *) &int_data[1];
  ps_params[1].length = 0;
  ps_params[1].is_null = 0;

  ps_params[2].buffer_type = MYSQL_TYPE_LONG;
  ps_params[2].buffer = (char *) &int_data[2];
  ps_params[2].length = 0;
  ps_params[2].is_null = 0;

  /* bind parameters */
  rc = mysql_stmt_bind_param(stmt, ps_params);
  check_stmt_rc(rc, stmt);

  /* assign values to parameters and execute statement */
  int_data[0]= 10;  /* p_in */
  int_data[1]= 20;  /* p_out */
  int_data[2]= 30;  /* p_inout */

  rc = mysql_stmt_execute(stmt);
  check_stmt_rc(rc, stmt);

  FAIL_IF(mysql_stmt_field_count(stmt) != 3, "expected 3 fields");

  memset(rs_bind, 0, sizeof (MYSQL_BIND) * 3);
  for (i=0; i < 3; i++)
  {
    rs_bind[i].buffer = (char *) &(int_data[i]);
    rs_bind[i].buffer_length = sizeof (int_data);
    rs_bind[i].buffer_type = MYSQL_TYPE_LONG;
    rs_bind[i].is_null = &is_null[i];
  }
  rc= mysql_stmt_bind_result(stmt, rs_bind);
  check_stmt_rc(rc, stmt);

  rc= mysql_stmt_fetch(stmt);
  check_stmt_rc(rc, stmt);
 
  FAIL_IF(int_data[0] != 10 || int_data[1] != 20 || int_data[2] != 30,
          "expected 10 20 30"); 

  FAIL_IF(mysql_stmt_next_result(stmt) != 0, "expected more results");
  rc= mysql_stmt_bind_result(stmt, rs_bind);

  rc= mysql_stmt_fetch(stmt);
  FAIL_IF(mysql_stmt_field_count(stmt) != 3, "expected 3 fields");
  FAIL_IF(int_data[0] != 100 || int_data[1] != 200 || int_data[2] != 300,
          "expected 100 200 300"); 

  FAIL_IF(mysql_stmt_next_result(stmt) != 0, "expected more results");
  rc= mysql_stmt_bind_result(stmt, rs_bind);

  rc= mysql_stmt_fetch(stmt);
  FAIL_IF(mysql_stmt_field_count(stmt) != 2, "expected 2 fields");
  FAIL_IF(int_data[0] != 200 || int_data[1] != 300,
          "expected 100 200 300"); 
  
  FAIL_IF(mysql_stmt_next_result(stmt) != 0, "expected more results");
  FAIL_IF(mysql_stmt_field_count(stmt) != 0, "expected 0 fields");

  rc= mysql_stmt_close(stmt);
  check_stmt_rc(rc, stmt);
}

struct my_tests_st my_tests[] = {
  {"test_multi_result", test_multi_result, TEST_CONNECTION_NEW, CLIENT_MULTI_STATEMENTS, NULL , NULL},
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
