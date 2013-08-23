/*
Copyright (c) 2013 Monty Program AB. All rights reserved.

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

#include "my_test.h"
#include <locale.h>


typedef struct {
  char *cs_from;
  char *cs_to;
  char *hex_source;
  char *source;
  size_t len;
} CS_CONV;



static int test_cs_conversion(MYSQL *mysql)
{
  CS_CONV cs_conv[]= { {"latin1", "utf8", NULL, "Günter André",0},
                       {"koi8r", "utf8", NULL, "×ÁÓÑ", 0},
                       {"koi8r", "utf8", NULL, "÷áóñ", 0},
                       {"koi8r", "utf8", NULL, "É", 0},
                       {"koi8r", "utf8", NULL, "Ê", 0},
                       {"ucs2", "utf8", "0x0041040B", "\x00\x41\x04\x0B", 4},
                       {"ucs2", "utf8", "0x039C03C903B4", "\x03\x9C\x03\xC9\x03\xB4",6},
                       {"ucs2", "utf8", "0x039C03C903B403B11F770308", "\x03\x9C\x03\xC9\x03\xB4\x03\xB1\x1F\x77\x03\x08", 0},
                       {"ucs2", "utf8", "0x0030", "\x00\x30", 2},
                       {"ucs2", "utf8", NULL, "£Ã£±", 0},
                       {"ucs2", "utf8", NULL, "£Ã£±", 0},
                       {"ucs2", "utf8", NULL, "£Ã£±", 0},
                       {"ucs2", "sjis", NULL, "£Ã£±", 0},
                       {"ucs2", "ujis", NULL, "£Ã£±", 0},
                       {"eucjpms", "ujis", NULL, "ï¼£ï¼", 0},
                       {"latin1", "sjis", NULL, "ï¼£ï¼", 0},
                       {"utf8", "latin1", NULL, "ï¼£ï¼", 0},
                       /* C8 pane not supported
                       {"big5", "utf8", "0xC84041", "\xC8\x40\x41", 0}, */
                       {"latin1", "utf8", "0xFF8F", "\xFF\x8F", 0},
                       {NULL, NULL, NULL}
                     };
  int i= 0, rc;

  setlocale(LC_ALL, "en_GB");

  while (cs_conv[i].cs_from)
  {
    char query[1024];
    size_t from_len, to_len= 1024;
    CHARSET_INFO *cs_from, *cs_to;
    MYSQL_RES *res;
    MYSQL_ROW row;
    char str_converted[1024];
    char str_expected[1024];
    memset(str_converted, 0, 1024);
    memset(str_expected, 0, 1024);

    FAIL_IF(!(cs_from= get_charset_by_name(cs_conv[i].cs_from)), "invalid character set");
    FAIL_IF(!(cs_to= get_charset_by_name(cs_conv[i].cs_to)), "invalid character set");


    snprintf(query, 1024, "SET NAMES %s", cs_conv[i].cs_to);
    rc= mysql_query(mysql, query);
    check_mysql_rc(rc, mysql);

    snprintf(query, 1024, "SELECT CONVERT(_%s %s%s%s using %s)",
                    cs_conv[i].cs_from,
                    cs_conv[i].hex_source ? "" : "\"",
                    cs_conv[i].hex_source ? cs_conv[i].hex_source : cs_conv[i].source,
                    cs_conv[i].hex_source ? "" : "\"",
                    cs_conv[i].cs_to);
    rc= mysql_query(mysql, query);
    check_mysql_rc(rc, mysql);

    res= mysql_store_result(mysql);
    FAIL_IF(!res, "expected result set");
 
    FAIL_IF(!(row= mysql_fetch_row(res)), "fetching row failed");
    strcpy(str_converted, row[0]);
    mysql_free_result(res);

    from_len= cs_conv[i].len ? cs_conv[i].len : strlen(cs_conv[i].source);
    FAIL_IF(convert_string(cs_conv[i].source, &from_len, cs_from,
                            str_expected, &to_len, cs_to) < 1, "conversion error occured");

    if (strcmp(str_converted, str_expected))
    {
      diag("Error converting from %s to %s\ndb:'%s' library: '%s'", 
            cs_from->csname, cs_to->csname, str_converted, str_expected);
      return FAIL;
    }
    i++;
  }
                       
  return OK;
}

struct my_tests_st my_tests[] = {
  {"test_cs_conversion", test_cs_conversion, TEST_CONNECTION_NEW, 0, NULL, NULL}, 
  {NULL, NULL, 0, 0, NULL, 0}
};


int main(int argc, char **argv)
{
  if (argc > 1)
   get_options(argc, argv);

  get_envvars();

  run_tests(my_tests);

  return(exit_status());
}
