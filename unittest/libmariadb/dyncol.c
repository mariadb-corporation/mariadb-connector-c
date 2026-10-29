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
#include "mariadb_dyncol.h"

static int create_dyncol_named(MYSQL *mysql)
{
  DYNAMIC_COLUMN dyncol;
  DYNAMIC_COLUMN_VALUE *vals;
  uint i, column_count= 6;
  int rc;
  const char *strval[]= {"Val1", "Val2", "Val3", "Val4", "Val5", "Val6"};
  MYSQL_LEX_STRING keys1[]= {{(char *)"key1", 4}, {(char *)"key2", 4},
                             {(char *)"key3", 4}, {(char *)"key4", 4},
                             {(char *)"key5", 4}, {(char *)"key6", 4}},

                   keys2[]= {{(char *)"key1", 4}, {(char *)"key1", 4},
                             {(char *)"key3", 4}, {(char *)"key4", 4},
                             {(char *)"key5", 4}, {(char *)"key6", 4}},

                   keys3[]= {{(char *)"\x70\x61\x72\x61\x00\x30", 6}, 
                             {(char *)"\x70\x61\x72\x61\x00\x31", 6},
                             {(char *)"\x70\x61\x72\x61\x00\x32", 6},
                             {(char *)"\x70\x61\x72\x61\x00\x33", 6},
                             {(char *)"\x70\x61\x72\x61\x00\x34", 6},
                             {(char *)"\x70\x61\x72\x61\x00\x35", 6}};
  MYSQL_LEX_STRING *my_keys;
  uint my_count;

  vals= (DYNAMIC_COLUMN_VALUE *)malloc(column_count * sizeof(DYNAMIC_COLUMN_VALUE));
  check(vals);

  for (i=0; i < column_count; i++)
  {
    vals[i].type= DYN_COL_STRING;
    vals[i].x.string.value.str= (char *)strval[i];
    vals[i].x.string.value.length= strlen(strval[i]);
    vals[i].x.string.charset= (MARIADB_CHARSET_INFO *)mysql->charset;
    diag("%s", keys3[i].str);
  }

  mariadb_dyncol_init(&dyncol);
  rc= mariadb_dyncol_create_many_named(&dyncol, column_count, keys1, vals, 0); 
  mariadb_dyncol_free(&dyncol);
  FAIL_IF(mariadb_dyncol_create_many_named(&dyncol, column_count, keys1, vals, 1) < 0, "Error");
  column_count= 0;
  FAIL_IF(mariadb_dyncol_column_count(&dyncol, &column_count) < 0, "Error");

  FAIL_IF(column_count != 6, "6 columns expected");
  mariadb_dyncol_free(&dyncol);

  rc= mariadb_dyncol_create_many_named(&dyncol, column_count, keys3, vals, 1);
  if (rc < 0) {
    diag("Error!!: %d", rc);
    return FAIL;
  } 
  column_count= 0;
  FAIL_IF(mariadb_dyncol_column_count(&dyncol, &column_count) < 0, "Error");

  FAIL_IF(column_count != 6, "6 columns expected");

  mariadb_dyncol_free(&dyncol);

  /* Now try to add a duplicate key */

  FAIL_IF(mariadb_dyncol_create_many_named(&dyncol, column_count, keys2, vals, 1) >=0, "Error expected");
  mariadb_dyncol_free(&dyncol);

  /* binary keys */
  rc= mariadb_dyncol_create_many_named(&dyncol, column_count, keys3, vals, 1);
  FAIL_IF(rc < 0, "binary keys failed");

  /* get keys*/
  rc= mariadb_dyncol_list_named(&dyncol, &my_count, &my_keys);
  FAIL_IF(rc < 0, "list named failed");

  for (i=0; i < my_count; i++)
  {
    if (memcmp(my_keys[i].str, keys3[i].str, keys3[i].length) != 0)
      diag("error key %d", i);
    vals[i].type=DYN_COL_NULL;
  }
  rc= mariadb_dyncol_update_many_named(&dyncol, column_count, keys3, vals);
  FAIL_IF(rc < 0, "update failed");
  mariadb_dyncol_free(&dyncol);

  keys3[0].str= (char *)"test";
  for (i=0; i < column_count; i++)
    diag("%s", my_keys[i].str);

  free(vals);
  free(my_keys);
  return OK; 
}

static int mdev_4994(MYSQL *unused __attribute__((unused)))
{
  DYNAMIC_COLUMN dyncol;
  uint key= 1;
  DYNAMIC_COLUMN_VALUE val;
  int rc;
  

  val.type= DYN_COL_NULL;

  mariadb_dyncol_init(&dyncol);
  rc= mariadb_dyncol_create_many_num(&dyncol, 1, &key, &val, 0); 
  FAIL_IF(rc < 0, "Unexpected error");
  mariadb_dyncol_free(&dyncol);
  return OK;
}

static int create_dyncol_num(MYSQL *mysql)
{
  DYNAMIC_COLUMN dyncol;
  DYNAMIC_COLUMN_VALUE vals[5];
  uint i, column_count= 5;
  uint my_count;
  MYSQL_LEX_STRING *my_keys;
  DYNAMIC_COLUMN_VALUE *my_vals;
  int rc;
  const char *strval[]= {"Val1", "Val2", "Val3", "Val4", "Val5"};

  uint keys1[5]= {1,2,3,4,5},
       keys2[5]= {1,2,2,4,5};
  MYSQL_LEX_STRING key1= {(char *)"1",1};

  for (i=0; i < column_count; i++)
  {
    vals[i].type= DYN_COL_STRING;
    vals[i].x.string.value.str= (char *)strval[i];
    vals[i].x.string.value.length= strlen(strval[i]);
    vals[i].x.string.charset= (MARIADB_CHARSET_INFO *)mysql->charset;
  }
  FAIL_IF(mariadb_dyncol_create_many_num(&dyncol, column_count, keys1, vals, 1) <0, "Error (keys1)");

  vals[0].x.string.value.str= (char *)strval[1];
  rc= mariadb_dyncol_update_many_named(&dyncol,1, &key1, vals);
  diag("update: %d", rc);

  rc= mariadb_dyncol_unpack(&dyncol, &my_count, &my_keys, &my_vals);
  diag("unpack: %d %d", rc, my_count);

  free(my_keys);
  free(my_vals);

  FAIL_IF(mariadb_dyncol_column_count(&dyncol, &column_count) < 0, "Error");
  FAIL_IF(column_count != 5, "5 columns expected");
  mariadb_dyncol_free(&dyncol);
  FAIL_IF(mariadb_dyncol_create_many_num(&dyncol, column_count, keys2, vals, 1) >=0, "Error expected (keys2)");
  mariadb_dyncol_free(&dyncol);
  return OK;
}

static int mdev_x1(MYSQL *mysql)
{
  int rc;
  uint i;
  uint num_keys[5]= {1,2,3,4,5};
  const char *strval[]= {"Val1", "Val2", "Val3", "Val4", "Val5"};
  DYNAMIC_COLUMN_VALUE vals[5];
  DYNAMIC_COLUMN dynstr;
  MYSQL_LEX_STRING my_key= {(char *)"1", 2};
  uint unpack_columns;
  MYSQL_LEX_STRING *unpack_keys;
  DYNAMIC_COLUMN_VALUE *unpack_vals;

  for (i=0; i < 5; i++)
  {
    vals[i].type= DYN_COL_STRING;
    vals[i].x.string.value.str= (char *)strval[i];
    vals[i].x.string.value.length= strlen(strval[i]);
    vals[i].x.string.charset= (MARIADB_CHARSET_INFO *)mysql->charset;
  }

  mariadb_dyncol_init(&dynstr);

  /* create numeric */
  rc= mariadb_dyncol_create_many_num(&dynstr, 5, num_keys, vals, 1);
  if (rc < 0)
  {
    diag("Error: %d", rc);
    return FAIL;
  }

  /* unpack and print values */
  rc= mariadb_dyncol_unpack(&dynstr, &unpack_columns, &unpack_keys, &unpack_vals);
  if (rc < 0)
  {
    diag("Error: %d", rc);
    return FAIL;
  }

  for (i=0; i < unpack_columns; i++)
    if (memcmp(unpack_vals[i].x.string.value.str, vals[i].x.string.value.str, vals[i].x.string.value.length))
      diag("Error1: key: %1s val: %s %s", unpack_keys[i].str, unpack_vals[i].x.string.value.str, vals[i].x.string.value.str);

  free(unpack_keys);
  free(unpack_vals);

  /* change one value and update with named key */
/*  vals[0].x.string.value.str= strval[1]; */
  rc= mariadb_dyncol_update_many_named(&dynstr, 1, &my_key, vals);
  if (rc < 0)
  {
    diag("Error: %d", rc);
    return FAIL;
  }

  /* unpack and print values */
  rc= mariadb_dyncol_unpack(&dynstr, &unpack_columns, &unpack_keys, &unpack_vals);
  if (rc < 0)
  {
    diag("Error: %d", rc);
    return FAIL;
  }
  diag("Columns: %d", unpack_columns);

  for (i=0; i < unpack_columns; i++)
    diag("Key: %s Len: %lu", unpack_keys[i].str, (unsigned long)unpack_keys[i].length);


  free(unpack_keys);
  free(unpack_vals);

  mariadb_dyncol_free(&dynstr);
  return OK;
}

static int dyncol_column_count(MYSQL *unused __attribute__((unused)))
{
  DYNAMIC_COLUMN dyncol;
  uint column_count= 5;
  int rc;

  mariadb_dyncol_init(&dyncol); /* memset(&dyncol, 0, sizeof(DYNAMIC_COLUMN)) */
  rc= mariadb_dyncol_column_count(&dyncol, &column_count);
  diag("rc=%d", rc);
  FAIL_IF(rc < 0, "unexpected error");
  FAIL_IF(column_count > 0, "Expected column_count=0");  
  return OK;
}

static int dyncol_nested(MYSQL *mysql __attribute__((unused)))
{
  DYNAMIC_COLUMN col1, col2;
  DYNAMIC_COLUMN_VALUE value[2];
  MYSQL_LEX_STRING cols[2]= {{(char *)"0",1},{(char *)"1",1}};
  DYNAMIC_STRING s;

  mariadb_dyncol_init(&col1);
  mariadb_dyncol_init(&col2);

  memset(&value, 0, sizeof(DYNAMIC_COLUMN_VALUE));

  value[0].type= DYN_COL_UINT;
  value[0].x.ulong_value = 17;

  mariadb_dyncol_create_many_named(&col1, 1, cols, value, 0);
  if (mariadb_dyncol_check(&col1) != ER_DYNCOL_OK)
  {
    diag("Error while creating col1");
    return FAIL;
  }

  value[1].type= DYN_COL_DYNCOL;
  value[1].x.string.value.str= col1.str;
  value[1].x.string.value.length= col1.length;
 
  mariadb_dyncol_create_many_named(&col2, 2, cols, value, 0);
  if (mariadb_dyncol_check(&col2) != ER_DYNCOL_OK)
  {
    diag("Error while creating col1");
    return FAIL;
  }
  mariadb_dyncol_json(&col2, &s);
  if (strcmp(s.str, "{\"0\":17,\"1\":{\"0\":17}}") != 0)
  {
    diag("%s != %s", s.str, "{\"0\":17,\"1\":{\"0\":17}}");
    return FAIL;
  }
  ma_dynstr_free(&s);
  mariadb_dyncol_free(&col1);
  mariadb_dyncol_free(&col2);
  return OK;
}

static int test_conc844(MYSQL *mysql __attribute__((unused)))
{
  DYNAMIC_COLUMN str;
  enum enum_dyncol_func_result rc;
  DYNAMIC_COLUMN_VALUE value;
  MYSQL_LEX_STRING ls= {(char*)"test_key", 8};

  uchar corrupted_blob[] = {
    0x04,                   /* Format byte: offset_size = 2, fixed_hdr = 5 */
    0x02, 0x00,             /* Column count = 2 */
    0xFF, 0x0F              /* nmpool_size = 4095 bytes (exceeds actual blob length) */
  };


  memset(&str, 0, sizeof(str));
  str.str = (char *)corrupted_blob;
  str.length = sizeof(corrupted_blob); /* Total buffer length is only 5 bytes */

  /* Call a public API function that invokes init_read_hdr() */
  rc = mariadb_dyncol_get_named(&str, &ls, &value);

  /* Before fix: Crashes / OOB read / returns unexpected error */
  /* After fix:  Must safely return ER_DYNCOL_FORMAT */
  FAIL_IF(rc != ER_DYNCOL_FORMAT, "expected format error");

  return OK;
}

static int test_int_overflow(MYSQL *mysql __attribute__((unused)))
{
  DYNAMIC_COLUMN str;
  DYNAMIC_COLUMN bad;
  DYNAMIC_COLUMN_VALUE val, res;
  uint column_nr= 1;
  DYNAMIC_COLUMN_TYPE type[2]= {DYN_COL_INT, DYN_COL_UINT};
  int rc, i;

  for (i=0; i < 2; i++) {
    val.type= type[i];
    if (i)
      val.x.ulong_value= 1;
    else
      val.x.long_value= 1;

    rc= mariadb_dyncol_create_many_num(&str, 1, &column_nr, &val, 1);
    if (rc != ER_DYNCOL_OK) {
      diag("failed to create_many_num");
      return FAIL;
    }

    /* widen the single column's data interval past 8 bytes */
    bad.length= str.length + 12;
    bad.max_length= bad.length;
    bad.alloc_increment= 0;
    if (!(bad.str= (char *) malloc(bad.length))) {
      diag("out of memory");
      mariadb_dyncol_free(&str);
      return FAIL;
    }
    memcpy(bad.str, str.str, str.length);
    memset(bad.str + str.length, 0, 12);

    rc= mariadb_dyncol_get_num(&bad, column_nr, &res);
    if (rc != ER_DYNCOL_FORMAT) {
      free(bad.str);
      mariadb_dyncol_free(&str);
      diag("Format error expected");
      return FAIL;
    }

    free(bad.str);
    mariadb_dyncol_free(&str);
  }

  return OK;
}

static int test_conc864(MYSQL *mysql __attribute__((unused)))
{
  DYNAMIC_COLUMN dc, bad;
  MYSQL_LEX_STRING keys[2]= {{(char *)"a", 1}, {(char *)"bb", 2}};
  DYNAMIC_COLUMN_VALUE vals[2];
  MYSQL_LEX_STRING *names= NULL;
  unsigned char *blob;
  uint count= 0;
  size_t len;
  int rc, result= FAIL;

  vals[0].type= DYN_COL_INT;
  vals[0].x.long_value= 1;
  vals[1].type= DYN_COL_INT;
  vals[1].x.long_value= 2;

  mariadb_dyncol_init(&dc);
  FAIL_IF(mariadb_dyncol_create_many_named(&dc, 2, keys, vals, 1) != ER_DYNCOL_OK,
          "could not create the dynamic column");

  len= dc.length;
  blob= (unsigned char *)malloc(len);
  FAIL_IF(!blob, "malloc failed");
  memcpy(blob, dc.str, len);
  mariadb_dyncol_free(&dc);

  if (!(blob[0] & 0x04) || blob[5] != 0 || blob[6] != 0)
  {
    diag("unexpected layout of the dynamic column, update the test");
    goto end;
  }

  blob[5]= 0xFF;                    /* entry 0: name offset 0xFFFF */
  blob[6]= 0xFF;

  memset(&bad, 0, sizeof(bad));
  bad.str= (char *)blob;
  bad.length= len;
  bad.max_length= len;

  rc= mariadb_dyncol_list_named(&bad, &count, &names);
  if (rc != ER_DYNCOL_FORMAT)
  {
    diag("list_named returned %d, expected ER_DYNCOL_FORMAT", rc);
    free(names);
    goto end;
  }
  if (names != NULL || count != 0)
  {
    diag("list_named left names=%p count=%u after an error", (void *)names, count);
    free(names);                    /* do not leak it from the test */
    goto end;
  }
  result= OK;

end:
  free(blob);
  return result;
}

/* Paste above "struct my_tests_st my_tests[]" in unittest/libmariadb/dyncol.c
   (test_dyncol_name_offsets_decreasing is already there). */

/*
  Layout of the packed column {a: 1, bb: 2, ccc: 3} (named format):
    bytes 0..4    flags (0x04 = named), column count, name pool size (6)
    bytes 5..16   3 entries of 4 bytes: name offset (2) + data offset/type (2)
                  name offsets: 0, 1, 3  (at bytes 5, 9 and 13)
    bytes 17..22  name pool "abbccc"
    then the data
*/

/* returns an exactly sized heap copy of a packed named column, or NULL */
static unsigned char *dc_named_blob(uint n, MYSQL_LEX_STRING *keys,
                                    DYNAMIC_COLUMN_VALUE *vals, size_t *len)
{
  DYNAMIC_COLUMN dc;
  unsigned char *blob;

  mariadb_dyncol_init(&dc);
  if (mariadb_dyncol_create_many_named(&dc, n, keys, vals, 1) != ER_DYNCOL_OK)
    return NULL;
  *len= dc.length;
  blob= (unsigned char *)malloc(dc.length);
  if (blob)
    memcpy(blob, dc.str, dc.length);
  mariadb_dyncol_free(&dc);
  return blob;
}

static void dc_abc_setup(MYSQL_LEX_STRING *keys, DYNAMIC_COLUMN_VALUE *vals)
{
  uint i;

  keys[0].str= (char *)"a";   keys[0].length= 1;
  keys[1].str= (char *)"bb";  keys[1].length= 2;
  keys[2].str= (char *)"ccc"; keys[2].length= 3;
  for (i= 0; i < 3; i++)
  {
    vals[i].type= DYN_COL_INT;
    vals[i].x.long_value= i + 1;
  }
}

static int dc_layout_ok(const unsigned char *b, size_t len)
{
  return len >= 23 && (b[0] & 0x04) &&
         b[3] == 6 && b[4] == 0 &&                      /* pool size 6 */
         b[5] == 0 && b[6] == 0 &&                      /* entry 0: offset 0 */
         b[9] == 1 && b[10] == 0 &&                     /* entry 1: offset 1 */
         b[13] == 3 && b[14] == 0;                      /* entry 2: offset 3 */
}

/*
  The name offset of entry 1 is set behind the offset of entry 2, so that
  the decrease is not at the first pair of entries. The blob must be rejected
  by list_named and unpack, without reading or writing out of bounds.
*/
static int test_conc863_1(MYSQL *mysql __attribute__((unused)))
{
  MYSQL_LEX_STRING keys[3];
  DYNAMIC_COLUMN_VALUE vals[3];
  MYSQL_LEX_STRING *names= NULL;
  DYNAMIC_COLUMN_VALUE *uvals= NULL;
  DYNAMIC_COLUMN bad;
  unsigned char *blob;
  uint count= 0;
  size_t len= 0;
  int rc, result= FAIL;

  dc_abc_setup(keys, vals);
  blob= dc_named_blob(3, keys, vals, &len);
  FAIL_IF(!blob, "could not create the dynamic column");
  if (!dc_layout_ok(blob, len))
  {
    diag("unexpected layout of the dynamic column, update the test");
    goto end;
  }

  blob[9]= 4;                       /* entry 1: offset 4, entry 2: offset 3 */

  memset(&bad, 0, sizeof(bad));
  bad.str= (char *)blob;
  bad.length= len;
  bad.max_length= len;

  rc= mariadb_dyncol_list_named(&bad, &count, &names);
  free(names);
  names= NULL;
  if (rc != ER_DYNCOL_FORMAT)
  {
    diag("list_named returned %d, expected ER_DYNCOL_FORMAT", rc);
    goto end;
  }

  rc= mariadb_dyncol_unpack(&bad, &count, &names, &uvals);
  free(names);
  free(uvals);
  if (rc != ER_DYNCOL_FORMAT)
  {
    diag("unpack returned %d, expected ER_DYNCOL_FORMAT", rc);
    goto end;
  }
  result= OK;

end:
  free(blob);
  return result;
}

/* The check must not reject valid data: names of different lengths. */
static int test_conc863_2(MYSQL *mysql __attribute__((unused)))
{
  MYSQL_LEX_STRING keys[3];
  DYNAMIC_COLUMN_VALUE vals[3];
  MYSQL_LEX_STRING *names= NULL;
  DYNAMIC_COLUMN_VALUE *uvals= NULL;
  DYNAMIC_COLUMN dc;
  unsigned char *blob;
  uint i, count= 0;
  size_t len= 0;
  int rc, result= FAIL;

  dc_abc_setup(keys, vals);
  blob= dc_named_blob(3, keys, vals, &len);
  FAIL_IF(!blob, "could not create the dynamic column");

  memset(&dc, 0, sizeof(dc));
  dc.str= (char *)blob;
  dc.length= len;
  dc.max_length= len;

  rc= mariadb_dyncol_list_named(&dc, &count, &names);
  if (rc != ER_DYNCOL_OK || count != 3)
  {
    diag("list_named: rc=%d count=%u", rc, count);
    free(names);
    goto end;
  }
  for (i= 0; i < 3; i++)
  {
    if (names[i].length != keys[i].length ||
        memcmp(names[i].str, keys[i].str, keys[i].length))
    {
      diag("list_named: wrong name at position %u", i);
      free(names);
      goto end;
    }
  }
  free(names);
  names= NULL;

  rc= mariadb_dyncol_unpack(&dc, &count, &names, &uvals);
  if (rc != ER_DYNCOL_OK || count != 3)
  {
    diag("unpack: rc=%d count=%u", rc, count);
    free(names);
    free(uvals);
    goto end;
  }
  for (i= 0; i < 3; i++)
  {
    if (names[i].length != keys[i].length ||
        memcmp(names[i].str, keys[i].str, keys[i].length) ||
        uvals[i].type != DYN_COL_INT || uvals[i].x.long_value != (longlong)(i + 1))
    {
      diag("unpack: wrong name or value at position %u", i);
      free(names);
      free(uvals);
      goto end;
    }
  }
  free(names);
  free(uvals);

  if (mariadb_dyncol_check(&dc) != ER_DYNCOL_OK)
  {
    diag("check rejected a valid column");
    goto end;
  }
  result= OK;

end:
  free(blob);
  return result;
}

/* Charset number is a varint directly in front of the string bytes */
static int test_dyncol_uca1400_charset(MYSQL *unused __attribute__((unused)))
{
  static const char needle[]= "xyzzy";
  unsigned int tl;

  /* loop: undefined tailorings */
  for (tl= 26; tl <= 31; tl++)
  {
    DYNAMIC_COLUMN blob;
    DYNAMIC_COLUMN_VALUE val, out;
    uint colnr= 1;
    char *p;
    unsigned int bad_id= 2048 + tl * 8; /* 2256..2296, all two-byte varints */
    int rc;

    mariadb_dyncol_init(&blob);
    memset(&val, 0, sizeof(val));
    val.type= DYN_COL_STRING;
    val.x.string.value.str= (char *) needle;
    val.x.string.value.length= sizeof(needle) - 1;
    val.x.string.charset= mariadb_get_charset_by_nr(192);
    FAIL_IF(!val.x.string.charset, "charset 192 missing");

    rc= mariadb_dyncol_create_many_num(&blob, 1, &colnr, &val, 0);
    FAIL_IF(rc != ER_DYNCOL_OK, "create failed");

    /* control: the unpatched blob must read back fine */
    rc= mariadb_dyncol_get_num(&blob, colnr, &out);
    FAIL_IF(rc != ER_DYNCOL_OK, "control read failed");

    /* find the string; the 2-byte charset varint (C0 01) precedes it */
    p= (char *) memmem(blob.str, blob.length, needle, sizeof(needle) - 1);
    FAIL_IF(!p || p - blob.str < 2, "string not found in blob");
    FAIL_IF((uchar) p[-2] != 0xC0 || p[-1] != 0x01,
            "unexpected charset encoding, adjust the patch");

    p[-2]= (char) ((bad_id & 0x7F) | 0x80);
    p[-1]= (char) (bad_id >> 7);

    rc= mariadb_dyncol_get_num(&blob, colnr, &out);
    if (rc != ER_DYNCOL_UNKNOWN_CHARSET)
      diag("tailoring %u (id %u): got rc=%d", tl, bad_id, rc);
    FAIL_IF(rc != ER_DYNCOL_UNKNOWN_CHARSET,
            "undefined UCA1400 charset must be rejected");

    mariadb_dyncol_free(&blob);
  }
  return OK;
}

struct my_tests_st my_tests[] = {
  {"test_dyncol_uca1400_charset", test_dyncol_uca1400_charset, TEST_CONNECTION_NEW, 0, NULL, NULL},
  {"test_conc863_1", test_conc863_1, TEST_CONNECTION_NEW, 0, NULL, NULL},
  {"test_conc863_2", test_conc863_2, TEST_CONNECTION_NEW, 0, NULL, NULL},
  {"test_conc864", test_conc864, TEST_CONNECTION_NEW, 0, NULL, NULL},
  {"test_int_overflow", test_int_overflow, TEST_CONNECTION_NEW, 0, NULL, NULL}, 
  {"test_conc844", test_conc844, TEST_CONNECTION_NEW, 0, NULL, NULL}, 
  {"mdev_x1", mdev_x1, TEST_CONNECTION_NEW, 0, NULL, NULL}, 
  {"mdev_4994", mdev_4994, TEST_CONNECTION_NEW, 0, NULL, NULL}, 
  {"create_dyncol_named", create_dyncol_named, TEST_CONNECTION_NEW, 0, NULL, NULL}, 
  {"create_dyncol_num", create_dyncol_num, TEST_CONNECTION_NEW, 0, NULL, NULL}, 
  {"dyncol_column_count", dyncol_column_count, TEST_CONNECTION_NEW, 0, NULL, NULL}, 
  {"dyncol_nested", dyncol_nested, TEST_CONNECTION_NEW, 0, NULL, NULL}, 
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
