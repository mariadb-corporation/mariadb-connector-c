#include "my_test.h"

#define SENTINEL 0x5A5A5A5AUL   /* *len must keep this value on error */

typedef struct st_lenenc_case
{
  const char *name;
  unsigned char data[10];
  size_t size;                  /* number of valid bytes in data */
  unsigned int flags;
  int rc;                       /* expected return code */
  unsigned long len;            /* expected value (MARIADB_LENENC_OK only) */
  size_t consumed;              /* expected pos - buf (0 on error) */
} LENENC_CASE;

#define OK_    MARIADB_LENENC_OK
#define NULL_  MARIADB_LENENC_NULL
#define ERR_   MARIADB_LENENC_ERROR
#define FN     MARIADB_LENENC_FORBID_NULL

static const LENENC_CASE cases[]=
{
  /* name, data, size, flags, rc, len, consumed */
  {"empty buffer",              {0}, 0, 0,  ERR_, 0, 0},
  {"empty buffer, forbid NULL", {0}, 0, FN, ERR_, 0, 0},

  /* one byte values */
  {"zero",                      {0x00}, 1, 0, OK_, 0, 1},
  {"largest one byte value",    {0xFA}, 1, 0, OK_, 250, 1},

  /* 0xFB */
  {"NULL marker",               {0xFB}, 1, 0,  NULL_, 0, 1},
  {"NULL marker, then data",    {0xFB, 0x00}, 2, 0, NULL_, 0, 1},
  {"NULL marker forbidden",     {0xFB}, 1, FN, ERR_, 0, 0},

  /* 0xFF is never valid */
  {"0xFF",                      {0xFF}, 1, 0,  ERR_, 0, 0},
  {"0xFF, forbid NULL",         {0xFF}, 1, FN, ERR_, 0, 0},
  {"0xFF followed by data",     {0xFF, 0, 0, 0, 0, 0, 0, 0, 0}, 9, 0, ERR_, 0, 0},

  /* 0xFC: 2 byte value */
  {"0xFC, no payload",          {0xFC}, 1, 0, ERR_, 0, 0},
  {"0xFC, 1 payload byte",      {0xFC, 0x01}, 2, 0, ERR_, 0, 0},
  {"0xFC, 251 via prefix",      {0xFC, 0xFB, 0x00}, 3, 0, OK_, 251, 3},
  {"0xFC, 65535",               {0xFC, 0xFF, 0xFF}, 3, 0, OK_, 65535, 3},

  /* 0xFD: 3 byte value */
  {"0xFD, 2 payload bytes",     {0xFD, 0x01, 0x00}, 3, 0, ERR_, 0, 0},
  {"0xFD, 1",                   {0xFD, 0x01, 0x00, 0x00}, 4, 0, OK_, 1, 4},
  {"0xFD, 16777215",            {0xFD, 0xFF, 0xFF, 0xFF}, 4, 0, OK_, 16777215, 4},

  /* 0xFE: 8 byte value on the wire, only 32 bit values are accepted */
  {"0xFE, 7 payload bytes",     {0xFE, 0x01, 0, 0, 0, 0, 0, 0}, 8, 0, ERR_, 0, 0},
  {"0xFE, 16",                  {0xFE, 0x10, 0, 0, 0, 0, 0, 0, 0}, 9, 0, OK_, 16, 9},
  {"0xFE, 0xFFFFFFFF",          {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0}, 9, 0, OK_, 0xFFFFFFFFUL, 9},
  {"0xFE, 2^32",                {0xFE, 0, 0, 0, 0, 0x01, 0, 0, 0}, 9, 0, ERR_, 0, 0},
  {"0xFE, 2^32 + 16 (must not decode as 16)",
                                {0xFE, 0x10, 0, 0, 0, 0x01, 0, 0, 0}, 9, 0, ERR_, 0, 0},
  {"0xFE, 2^64 - 1",            {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 9, 0, ERR_, 0, 0},

  /* only the prefix is consumed, the payload length is not checked here */
  {"value larger than the rest of the buffer",
                                {0x05, 0xAA, 0xBB}, 3, 0, OK_, 5, 1},

  /* unknown flag bits are rejected, even for valid input */
  {"unknown flag 0x2",          {0x00}, 1, 0x2, ERR_, 0, 0},
  {"unknown flag with FORBID_NULL", {0x00}, 1, FN | 0x2, ERR_, 0, 0},
  {"unknown high flag bit",     {0x00}, 1, 0x80000000U, ERR_, 0, 0},
};

static int run_case(const LENENC_CASE *c)
{
  /* exactly sized heap block, so that any overread is caught by ASan */
  unsigned char *buf= (unsigned char *)malloc(c->size ? c->size : 1);
  unsigned char *pos;
  unsigned long len= SENTINEL;
  unsigned long expected_len;
  int rc, failed= 0;

  if (!buf)
    return 1;
  if (c->size)
    memcpy(buf, c->data, c->size);
  pos= buf;

  rc= mariadb_net_field_length(&pos, buf + c->size, c->flags, &len);

  if (c->rc == OK_)
    expected_len= c->len;
  else if (c->rc == NULL_)
    expected_len= 0;
  else
    expected_len= SENTINEL;                 /* unchanged on error */

  if (rc != c->rc)
  {
    diag("%s: return code %d, expected %d", c->name, rc, c->rc);
    failed= 1;
  }
  if (len != expected_len)
  {
    diag("%s: len %lu, expected %lu", c->name, len, expected_len);
    failed= 1;
  }
  if (pos != buf + c->consumed)
  {
    diag("%s: consumed %ld bytes, expected %lu", c->name,
         (long)(pos - buf), (unsigned long)c->consumed);
    failed= 1;
  }
  free(buf);
  return failed;
}

static int test_lenenc_cases(MYSQL *unused __attribute__((unused)))
{
  size_t i;
  int failed= 0;

  for (i= 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    failed|= run_case(&cases[i]);

  FAIL_IF(failed, "mariadb_net_field_length returned unexpected results");
  return OK;
}

/*
  Every possible first byte with a buffer of exactly one byte:
  0..250 are values, 251 is NULL (unless forbidden), 252..255 need more
  bytes or are invalid.
*/
static int test_lenenc_first_byte(MYSQL *unused __attribute__((unused)))
{
  unsigned int b, f;
  int failed= 0;

  for (f= 0; f <= FN; f++)
  {
    for (b= 0; b < 256; b++)
    {
      unsigned char *buf= (unsigned char *)malloc(1);
      unsigned char *pos= buf;
      unsigned long len= SENTINEL;
      int rc, expected_rc;

      FAIL_IF(!buf, "malloc failed");
      buf[0]= (unsigned char)b;

      if (b <= 250)
        expected_rc= MARIADB_LENENC_OK;
      else if (b == 251 && !(f & FN))
        expected_rc= MARIADB_LENENC_NULL;
      else
        expected_rc= MARIADB_LENENC_ERROR;

      rc= mariadb_net_field_length(&pos, buf + 1, f, &len);

      if (rc != expected_rc ||
          (rc == MARIADB_LENENC_ERROR && (len != SENTINEL || pos != buf)) ||
          (rc == MARIADB_LENENC_OK && (len != b || pos != buf + 1)) ||
          (rc == MARIADB_LENENC_NULL && (len != 0 || pos != buf + 1)))
      {
        diag("first byte 0x%02X, flags %u: rc %d (expected %d)", b, f, rc, expected_rc);
        failed= 1;
      }
      free(buf);
    }
  }
  FAIL_IF(failed, "single byte buffers behave unexpectedly");
  return OK;
}

struct my_tests_st my_tests[]= {
  {"test_lenenc_cases",      test_lenenc_cases,      TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_lenenc_first_byte", test_lenenc_first_byte, TEST_CONNECTION_NONE, 0, NULL, NULL},
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
