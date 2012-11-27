/****************************************************************************
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
*****************************************************************************/

/* The implementation for character set support was ported from PHP's mysqlnd
   extension, written by Andrey Hristov, Georg Richter and Ulf Wendel 

   Original file header:
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2011 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Authors: Georg Richter <georg@mysql.com>                             |
  |          Andrey Hristov <andrey@mysql.com>                           |
  |          Ulf Wendel <uwendel@mysql.com>                              |
  +----------------------------------------------------------------------+
*/

#ifndef _WIN32
#include <strings.h>
#include <string.h>
#else
#include <string.h>
#endif
#include <my_global.h>
#include <m_ctype.h>

/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2011 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Authors: Georg Richter <georg@mysql.com>                             |
  |          Andrey Hristov <andrey@mysql.com>                           |
  |          Ulf Wendel <uwendel@mysql.com>                              |
  +----------------------------------------------------------------------+
*/

/* {{{ utf8 functions */
static unsigned int check_mb_utf8mb3_sequence(const char *start, const char *end)
{
  uchar  c;

  if (start >= end) {
    return 0;
  }

  c = (uchar) start[0];

  if (c < 0x80) {
    return 1;    /* single byte character */
  }
  if (c < 0xC2) {
    return 0;    /* invalid mb character */
  }
  if (c < 0xE0) {
    if (start + 2 > end) {
      return 0;  /* too small */
    }
    if (!(((uchar)start[1] ^ 0x80) < 0x40)) {
      return 0;
    }
    return 2;
  }
  if (c < 0xF0) {
    if (start + 3 > end) {
      return 0;  /* too small */
    }
    if (!(((uchar)start[1] ^ 0x80) < 0x40 && ((uchar)start[2] ^ 0x80) < 0x40 &&
      (c >= 0xE1 || (uchar)start[1] >= 0xA0))) {
      return 0;  /* invalid utf8 character */
    }
    return 3;
  }
  return 0;
}


static unsigned int check_mb_utf8_sequence(const char *start, const char *end)
{
  uchar  c;

  if (start >= end) {
    return 0;
  }

  c = (uchar) start[0];

  if (c < 0x80) {
    return 1;    /* single byte character */
  }
  if (c < 0xC2) {
    return 0;    /* invalid mb character */
  }
  if (c < 0xE0) {
    if (start + 2 > end) {
      return 0;  /* too small */
    }
    if (!(((uchar)start[1] ^ 0x80) < 0x40)) {
      return 0;
    }
    return 2;
  }
  if (c < 0xF0) {
    if (start + 3 > end) {
      return 0;  /* too small */
    }
    if (!(((uchar)start[1] ^ 0x80) < 0x40 && ((uchar)start[2] ^ 0x80) < 0x40 &&
      (c >= 0xE1 || (uchar)start[1] >= 0xA0))) {
      return 0;  /* invalid utf8 character */
    }
    return 3;
  }
  if (c < 0xF5) {
    if (start + 4 > end) { /* We need 4 characters */
      return 0;  /* too small */
    }

    /*
      UTF-8 quick four-byte mask:
      11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
      Encoding allows to encode U+00010000..U+001FFFFF

      The maximum character defined in the Unicode standard is U+0010FFFF.
      Higher characters U+00110000..U+001FFFFF are not used.

      11110000.10010000.10xxxxxx.10xxxxxx == F0.90.80.80 == U+00010000 (min)
      11110100.10001111.10111111.10111111 == F4.8F.BF.BF == U+0010FFFF (max)

      Valid codes:
      [F0][90..BF][80..BF][80..BF]
      [F1][80..BF][80..BF][80..BF]
      [F2][80..BF][80..BF][80..BF]
      [F3][80..BF][80..BF][80..BF]
      [F4][80..8F][80..BF][80..BF]
    */

    if (!(((uchar)start[1] ^ 0x80) < 0x40 &&
      ((uchar)start[2] ^ 0x80) < 0x40 &&
      ((uchar)start[3] ^ 0x80) < 0x40 &&
        (c >= 0xf1 || (uchar)start[1] >= 0x90) &&
        (c <= 0xf3 || (uchar)start[1] <= 0x8F)))
    {
      return 0;  /* invalid utf8 character */
    }
    return 4;
  }
  return 0;
}

static unsigned int check_mb_utf8mb3_valid(const char *start, const char *end)
{
  unsigned int len = check_mb_utf8mb3_sequence(start, end);
  return (len > 1)? len:0;
}

static unsigned int check_mb_utf8_valid(const char *start, const char *end)
{
  unsigned int len = check_mb_utf8_sequence(start, end);
  return (len > 1)? len:0;
}


static unsigned int mysql_mbcharlen_utf8mb3(unsigned int utf8)
{
  if (utf8 < 0x80) {
    return 1;    /* single byte character */
  }
  if (utf8 < 0xC2) {
    return 0;    /* invalid multibyte header */
  }
  if (utf8 < 0xE0) {
    return 2;    /* double byte character */
  }
  if (utf8 < 0xF0) {
    return 3;    /* triple byte character */
  }
  return 0;
}


static unsigned int mysql_mbcharlen_utf8(unsigned int utf8)
{
  if (utf8 < 0x80) {
    return 1;    /* single byte character */
  }
  if (utf8 < 0xC2) {
    return 0;    /* invalid multibyte header */
  }
  if (utf8 < 0xE0) {
    return 2;    /* double byte character */
  }
  if (utf8 < 0xF0) {
    return 3;    /* triple byte character */
  }
  if (utf8 < 0xF8) {
    return 4;    /* four byte character */
  }
  return 0;
}
/* }}} */


/* {{{ big5 functions */
#define valid_big5head(c)  (0xA1 <= (unsigned int)(c) && (unsigned int)(c) <= 0xF9)
#define valid_big5tail(c)  ((0x40 <= (unsigned int)(c) && (unsigned int)(c) <= 0x7E) || \
              (0xA1 <= (unsigned int)(c) && (unsigned int)(c) <= 0xFE))

#define isbig5code(c,d) (isbig5head(c) && isbig5tail(d))

static unsigned int check_mb_big5(const char *start, const char *end)
{
  return (valid_big5head(*(start)) && (end - start) > 1 && valid_big5tail(*(start + 1)) ? 2 : 0);
}


static unsigned int mysql_mbcharlen_big5(unsigned int big5)
{
  return (valid_big5head(big5)) ? 2 : 1;
}
/* }}} */


/* {{{ cp932 functions */
#define valid_cp932head(c) ((0x81 <= (c) && (c) <= 0x9F) || (0xE0 <= (c) && c <= 0xFC))
#define valid_cp932tail(c) ((0x40 <= (c) && (c) <= 0x7E) || (0x80 <= (c) && c <= 0xFC))


static unsigned int check_mb_cp932(const char *start, const char *end)
{
  return (valid_cp932head((uchar)start[0]) && (end - start >  1) &&
      valid_cp932tail((uchar)start[1])) ? 2 : 0;
}


static unsigned int mysql_mbcharlen_cp932(unsigned int cp932)
{
  return (valid_cp932head((uchar)cp932)) ? 2 : 1;
}
/* }}} */


/* {{{ euckr functions */
#define valid_euckr(c)  ((0xA1 <= (uchar)(c) && (uchar)(c) <= 0xFE))

static unsigned int check_mb_euckr(const char *start, const char *end)
{
  if (end - start <= 1) {
    return 0;  /* invalid length */
  }
  if (*(uchar *)start < 0x80) {
    return 0;  /* invalid euckr character */
  }
  if (valid_euckr(start[1])) {
    return 2;
  }
  return 0;
}


static unsigned int mysql_mbcharlen_euckr(unsigned int kr)
{
  return (valid_euckr(kr)) ? 2 : 1;
}
/* }}} */


/* {{{ eucjpms functions */
#define valid_eucjpms(c)     (((c) & 0xFF) >= 0xA1 && ((c) & 0xFF) <= 0xFE)
#define valid_eucjpms_kata(c)  (((c) & 0xFF) >= 0xA1 && ((c) & 0xFF) <= 0xDF)
#define valid_eucjpms_ss2(c)  (((c) & 0xFF) == 0x8E)
#define valid_eucjpms_ss3(c)  (((c) & 0xFF) == 0x8F)

static unsigned int check_mb_eucjpms(const char *start, const char *end)
{
  if (*((uchar *)start) < 0x80) {
    return 0;  /* invalid eucjpms character */
  }
  if (valid_eucjpms(start[0]) && (end - start) > 1 && valid_eucjpms(start[1])) {
    return 2;
  }
  if (valid_eucjpms_ss2(start[0]) && (end - start) > 1 && valid_eucjpms_kata(start[1])) {
    return 2;
  }
  if (valid_eucjpms_ss3(start[0]) && (end - start) > 2 && valid_eucjpms(start[1]) &&
    valid_eucjpms(start[2])) {
    return 2;
  }
  return 0;
}


static unsigned int mysql_mbcharlen_eucjpms(unsigned int jpms)
{
  if (valid_eucjpms(jpms) || valid_eucjpms_ss2(jpms)) {
    return 2;
  }
  if (valid_eucjpms_ss3(jpms)) {
    return 3;
  }
  return 1;
}
/* }}} */


/* {{{ gb2312 functions */
#define valid_gb2312_head(c)  (0xA1 <= (uchar)(c) && (uchar)(c) <= 0xF7)
#define valid_gb2312_tail(c)  (0xA1 <= (uchar)(c) && (uchar)(c) <= 0xFE)


static unsigned int check_mb_gb2312(const char *start, const char *end)
{
  return (valid_gb2312_head((unsigned int)start[0]) && end - start > 1 &&
      valid_gb2312_tail((unsigned int)start[1])) ? 2 : 0;
}


static unsigned int mysql_mbcharlen_gb2312(unsigned int gb)
{
  return (valid_gb2312_head(gb)) ? 2 : 1;
}
/* }}} */


/* {{{ gbk functions */
#define valid_gbk_head(c)  (0x81<=(uchar)(c) && (uchar)(c)<=0xFE)
#define valid_gbk_tail(c)  ((0x40<=(uchar)(c) && (uchar)(c)<=0x7E) || (0x80<=(uchar)(c) && (uchar)(c)<=0xFE))

static unsigned int check_mb_gbk(const char *start, const char *end)
{
  return (valid_gbk_head(start[0]) && (end) - (start) > 1 && valid_gbk_tail(start[1])) ? 2 : 0;
}

static unsigned int mysql_mbcharlen_gbk(unsigned int gbk)
{
  return (valid_gbk_head(gbk) ? 2 : 1);
}
/* }}} */


/* {{{ sjis functions */
#define valid_sjis_head(c)  ((0x81 <= (c) && (c) <= 0x9F) || (0xE0 <= (c) && (c) <= 0xFC))
#define valid_sjis_tail(c)  ((0x40 <= (c) && (c) <= 0x7E) || (0x80 <= (c) && (c) <= 0xFC))


static unsigned int check_mb_sjis(const char *start, const char *end)
{
  return (valid_sjis_head((uchar)start[0]) && (end - start) > 1 && valid_sjis_tail((uchar)start[1])) ? 2 : 0;
}


static unsigned int mysql_mbcharlen_sjis(unsigned int sjis)
{
  return (valid_sjis_head((uchar)sjis)) ? 2 : 1;
}
/* }}} */


/* {{{ ucs2 functions */
static unsigned int check_mb_ucs2(const char *start __attribute((unused)), const char *end __attribute((unused)))
{
  return 2; /* always 2 */
}

static unsigned int mysql_mbcharlen_ucs2(unsigned int ucs2 __attribute((unused)))
{
  return 2; /* always 2 */
}
/* }}} */


/* {{{ ujis functions */
#define valid_ujis(c)       ((0xA1 <= ((c)&0xFF) && ((c)&0xFF) <= 0xFE))
#define valid_ujis_kata(c)  ((0xA1 <= ((c)&0xFF) && ((c)&0xFF) <= 0xDF))
#define valid_ujis_ss2(c)   (((c)&0xFF) == 0x8E)
#define valid_ujis_ss3(c)   (((c)&0xFF) == 0x8F)

static unsigned int check_mb_ujis(const char *start, const char *end)
{
  if (*(uchar*)start < 0x80) {
    return 0;  /* invalid ujis character */
  }
  if (valid_ujis(*(start)) && valid_ujis(*((start)+1))) {
    return 2;
  }
  if (valid_ujis_ss2(*(start)) && valid_ujis_kata(*((start)+1))) {
    return 2;
  }
  if (valid_ujis_ss3(*(start)) && (end-start) > 2 && valid_ujis(*((start)+1)) && valid_ujis(*((start)+2))) {
    return 3;
  }
  return 0;
}


static unsigned int mysql_mbcharlen_ujis(unsigned int ujis)
{
  return (valid_ujis(ujis)? 2: valid_ujis_ss2(ujis)? 2: valid_ujis_ss3(ujis)? 3: 1);
}
/* }}} */



/* {{{ utf16 functions */
#define UTF16_HIGH_HEAD(x)  ((((uchar) (x)) & 0xFC) == 0xD8)
#define UTF16_LOW_HEAD(x)   ((((uchar) (x)) & 0xFC) == 0xDC)

static unsigned int check_mb_utf16(const char *start, const char *end)
{
  if (start + 2 > end) {
    return 0;
  }

  if (UTF16_HIGH_HEAD(*start)) {
    return (start + 4 <= end) && UTF16_LOW_HEAD(start[2]) ? 4 : 0;
  }

  if (UTF16_LOW_HEAD(*start)) {
    return 0;
  }
  return 2;
}


static uint mysql_mbcharlen_utf16(unsigned int utf16)
{
  return UTF16_HIGH_HEAD(utf16) ? 4 : 2;
}
/* }}} */


/* {{{ utf32 functions */
static uint
check_mb_utf32(const char *start __attribute((unused)), const char *end __attribute((unused)))
{
  return 4;
}


static uint
mysql_mbcharlen_utf32(unsigned int utf32 __attribute((unused)))
{
  return 4;
}
/* }}} */

/*
  The server compiles sometimes the full utf-8 (the mb4) as utf8m4, and the old as utf8,
  for BC reasons. Sometimes, utf8mb4 is just utf8 but the old charsets are utf8mb3.
  Change easily now, with a macro, could be made compilastion dependable.
*/

#define UTF8_MB4 "utf8mb4"
#define UTF8_MB3 "utf8"

/* {{{ mysql_charsets */
const CHARSET_INFO compiled_charsets[] =
{
  {   1, 1, "big5","big5_chinese_ci", "", "", 1, 2, mysql_mbcharlen_big5, check_mb_big5},
  {   3, 1, "dec8", "dec8_swedisch_ci", "", "", 1, 1, NULL, NULL},
  {   4, 1, "cp850", "cp850_general_ci", "", "", 1, 1, NULL, NULL},
  {   6, 1, "hp8", "hp8_english_ci", "", "", 1, 1, NULL, NULL},
  {   7, 1, "koi8r", "koi8r_general_ci", "", "", 1, 1, NULL, NULL},
  {   8, 1, "latin1", "latin1_swedish_ci", "", "", 1, 1, NULL, NULL},
  {   9, 1, "latin2", "latin2_general_ci", "", "", 1, 1, NULL, NULL},
  {  10, 1, "swe7", "swe7_swedish_ci", "", "", 1, 1, NULL, NULL},
  {  11, 1, "ascii", "ascii_general_ci", "", "", 1, 1, NULL, NULL},
  {  12, 1, "ujis", "ujis_japanese_ci", "", "", 1, 3, mysql_mbcharlen_ujis, check_mb_ujis},
  {  13, 1, "sjis", "sjis_japanese_ci", "", "", 1, 2, mysql_mbcharlen_sjis, check_mb_sjis},
  {  16, 1, "hebrew", "hebrew_general_ci", "", "", 1, 1, NULL, NULL},
  {  18, 1, "tis620", "tis620_thai_ci", "", "", 1, 1, NULL, NULL},
  {  19, 1, "euckr", "euckr_korean_ci", "", "", 1, 2, mysql_mbcharlen_euckr, check_mb_euckr},
  {  22, 1, "koi8u", "koi8u_general_ci", "", "", 1, 1, NULL, NULL},
  {  24, 1, "gb2312", "gb2312_chinese_ci", "", "", 1, 2, mysql_mbcharlen_gb2312, check_mb_gb2312},
  {  25, 1, "greek", "greek_general_ci", "", "", 1, 1, NULL, NULL},
  {  26, 1, "cp1250", "cp1250_general_ci", "", "", 1, 1, NULL, NULL},
  {  28, 1, "gbk", "gbk_chinese_ci", "", "", 1, 2, mysql_mbcharlen_gbk, check_mb_gbk},
  {  30, 1, "latin5", "latin5_turkish_ci", "", "", 1, 1, NULL, NULL},
  {  32, 1, "armscii8", "armscii8_general_ci", "", "", 1, 1, NULL, NULL},
  {  33, 1, UTF8_MB3, UTF8_MB3"_general_ci", "UTF-8 Unicode", "", 1, 3, mysql_mbcharlen_utf8mb3,  check_mb_utf8mb3_valid},
  {  35, 1, "ucs2", "ucs2_general_ci", "UCS-2 Unicode", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  {  36, 1, "cp866", "cp866_general_ci", "", "", 1, 1, NULL, NULL},
  {  37, 1, "keybcs2", "keybcs2_general_ci", "", "", 1, 1, NULL, NULL},
  {  38, 1, "macce", "macce_general_ci", "", "", 1, 1, NULL, NULL},
  {  39, 1, "macroman", "macroman_general_ci", "", "", 1, 1, NULL, NULL},
  {  40, 1, "cp852", "cp852_general_ci", "", "", 1, 1, NULL, NULL},
  {  41, 1, "latin7", "latin7_general_ci", "", "", 1, 1, NULL, NULL},
  {  51, 1, "cp1251", "cp1251_general_ci", "", "", 1, 1, NULL, NULL},
  {  57, 1, "cp1256", "cp1256_general_ci", "", "", 1, 1, NULL, NULL},
  {  59, 1, "cp1257", "cp1257_general_ci", "", "", 1, 1, NULL, NULL},
  {  63, 1, "binary", "binary", "", "", 1, 1, NULL, NULL},
  {  92, 1, "geostd8", "geostd8_general_ci", "", "", 1, 1, NULL, NULL},
  {  95, 1, "cp932", "cp932_japanese_ci", "", "", 1, 2, mysql_mbcharlen_cp932, check_mb_cp932},
  {  97, 1, "eucjpms", "eucjpms_japanese_ci", "", "", 1, 3, mysql_mbcharlen_eucjpms, check_mb_eucjpms},
  {   2, 1, "latin2", "latin2_czech_cs", "", "", 1, 1, NULL, NULL},
  {   5, 1, "latin1", "latin1_german_ci", "", "", 1, 1, NULL, NULL},
  {  14, 1, "cp1251", "cp1251_bulgarian_ci", "", "", 1, 1, NULL, NULL},
  {  15, 1, "latin1", "latin1_danish_ci", "", "", 1, 1, NULL, NULL},
  {  17, 1, "filename", "filename", "", "", 1, 5, NULL, NULL},
  {  20, 1, "latin7", "latin7_estonian_cs", "", "", 1, 1, NULL, NULL},
  {  21, 1, "latin2", "latin2_hungarian_ci", "", "", 1, 1, NULL, NULL},
  {  23, 1, "cp1251", "cp1251_ukrainian_ci", "", "", 1, 1, NULL, NULL},
  {  27, 1, "latin2", "latin2_croatian_ci", "", "", 1, 1, NULL, NULL},
  {  29, 1, "cp1257", "cp1257_lithunian_ci", "", "", 1, 1, NULL, NULL},
  {  31, 1, "latin1", "latin1_german2_ci", "", "", 1, 1, NULL, NULL},
  {  34, 1, "cp1250", "cp1250_czech_cs", "", "", 1, 1, NULL, NULL},
  {  42, 1, "latin7", "latin7_general_cs", "", "", 1, 1, NULL, NULL},
  {  43, 1, "macce", "macce_bin", "", "", 1, 1, NULL, NULL},
  {  44, 1, "cp1250", "cp1250_croatian_ci", "", "", 1, 1, NULL, NULL},
  {  45, 1, UTF8_MB4, UTF8_MB4"_general_ci", "UTF-8 Unicode", "", 1, 4, mysql_mbcharlen_utf8,  check_mb_utf8_valid},
  {  46, 1, UTF8_MB4, UTF8_MB4"_bin", "UTF-8 Unicode", "", 1, 4, mysql_mbcharlen_utf8,  check_mb_utf8_valid},
  {  47, 1, "latin1", "latin1_bin", "", "", 1, 1, NULL, NULL},
  {  48, 1, "latin1", "latin1_general_ci", "", "", 1, 1, NULL, NULL},
  {  49, 1, "latin1", "latin1_general_cs", "", "", 1, 1, NULL, NULL},
  {  50, 1, "cp1251", "cp1251_bin", "", "", 1, 1, NULL, NULL},
  {  52, 1, "cp1251", "cp1251_general_cs", "", "", 1, 1, NULL, NULL},
  {  53, 1, "macroman", "macroman_bin", "", "", 1, 1, NULL, NULL},
  {  54, 1, "utf16", "utf16_general_ci", "UTF_16 Unicode", "", 2, 4, mysql_mbcharlen_utf16, check_mb_utf16},
  {  55, 1, "utf16", "utf16_bin", "UTF-16 Unicode", "", 2, 4, mysql_mbcharlen_utf16, check_mb_utf16},
  {  58, 1, "cp1257", "cp1257_bin", "", "", 1, 1, NULL, NULL},
#ifdef USED_TO_BE_SO_BEFORE_MYSQL_5_5
  {  60, 1, "armascii8", "armascii8_bin", "", "", 1, 1, NULL, NULL},
#endif
  {  60, 1, "utf32", "utf32_general_ci", "UTF-32 Unicode", "", 4, 4, mysql_mbcharlen_utf32, check_mb_utf32},
  {  61, 1, "utf32", "utf32_bin", "UTF-32 Unicode", "", 4, 4, mysql_mbcharlen_utf32, check_mb_utf32},
  {  65, 1, "ascii", "ascii_bin", "", "", 1, 1, NULL, NULL},
  {  66, 1, "cp1250", "cp1250_bin", "", "", 1, 1, NULL, NULL},
  {  67, 1, "cp1256", "cp1256_bin", "", "", 1, 1, NULL, NULL},
  {  68, 1, "cp866", "cp866_bin", "", "", 1, 1, NULL, NULL},
  {  69, 1, "dec8", "dec8_bin", "", "", 1, 1, NULL, NULL},
  {  70, 1, "greek", "greek_bin", "", "", 1, 1, NULL, NULL},
  {  71, 1, "hebew", "hebrew_bin", "", "", 1, 1, NULL, NULL},
  {  72, 1, "hp8", "hp8_bin", "", "", 1, 1, NULL, NULL},
  {  73, 1, "keybcs2", "keybcs2_bin", "", "", 1, 1, NULL, NULL},
  {  74, 1, "koi8r", "koi8r_bin", "", "", 1, 1, NULL, NULL},
  {  75, 1, "koi8u", "koi8u_bin", "", "", 1, 1, NULL, NULL},
  {  77, 1, "latin2", "latin2_bin", "", "", 1, 1, NULL, NULL},
  {  78, 1, "latin5", "latin5_bin", "", "", 1, 1, NULL, NULL},
  {  79, 1, "latin7", "latin7_bin", "", "", 1, 1, NULL, NULL},
  {  80, 1, "cp850", "cp850_bin", "", "", 1, 1, NULL, NULL},
  {  81, 1, "cp852", "cp852_bin", "", "", 1, 1, NULL, NULL},
  {  82, 1, "swe7", "swe7_bin", "", "", 1, 1, NULL, NULL},
  {  93, 1, "geostd8", "geostd8_bin", "", "", 1, 1, NULL, NULL},
  {  83, 1, UTF8_MB3, UTF8_MB3"_bin", "UTF-8 Unicode", "", 1, 3, mysql_mbcharlen_utf8mb3,  check_mb_utf8mb3_valid},
  {  84, 1, "big5", "big5_bin", "", "", 1, 2, mysql_mbcharlen_big5, check_mb_big5},
  {  85, 1, "euckr", "euckr_bin", "", "", 1, 2, mysql_mbcharlen_euckr, check_mb_euckr},
  {  86, 1, "gb2312", "gb2312_bin", "", "", 1, 2, mysql_mbcharlen_gb2312, check_mb_gb2312},
  {  87, 1, "gbk", "gbk_bin", "", "", 1, 2, mysql_mbcharlen_gbk, check_mb_gbk},
  {  88, 1, "sjis", "sjis_bin", "", "", 1, 2, mysql_mbcharlen_sjis, check_mb_sjis},
  {  89, 1, "tis620", "tis620_bin", "", "", 1, 1, NULL, NULL},
  {  90, 1, "ucs2", "ucs2_bin", "UCS-2 Unicode", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  {  91, 1, "ujis", "ujis_bin", "", "", 1, 3, mysql_mbcharlen_ujis, check_mb_ujis},
  {  94, 1, "latin1", "latin1_spanish_ci", "", "", 1, 1, NULL, NULL},
  {  96, 1, "cp932", "cp932_bin", "", "", 1, 2, mysql_mbcharlen_cp932, check_mb_cp932},
  {  99, 1, "cp1250", "cp1250_polish_ci", "", "", 1, 1, NULL, NULL},
  {  98, 1, "eucjpms", "eucjpms_bin", "", "", 1, 3, mysql_mbcharlen_eucjpms, check_mb_eucjpms},
  { 128, 1, "ucs2", "ucs2_unicode_ci", "", "", 2, 2,  mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 129, 1, "ucs2", "ucs2_icelandic_ci", "", "", 2, 2,  mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 130, 1, "ucs2", "ucs2_latvian_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 131, 1, "ucs2", "ucs2_romanian_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 132, 1, "ucs2", "ucs2_slovenian_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 133, 1, "ucs2", "ucs2_polish_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 134, 1, "ucs2", "ucs2_estonian_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 135, 1, "ucs2", "ucs2_spanish_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 136, 1, "ucs2", "ucs2_swedish_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 137, 1, "ucs2", "ucs2_turkish_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 138, 1, "ucs2", "ucs2_czech_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 139, 1, "ucs2", "ucs2_danish_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 140, 1, "ucs2", "ucs2_lithunian_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 141, 1, "ucs2", "ucs2_slovak_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 142, 1, "ucs2", "ucs2_spanish2_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 143, 1, "ucs2", "ucs2_roman_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 144, 1, "ucs2", "ucs2_persian_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 145, 1, "ucs2", "ucs2_esperanto_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 146, 1, "ucs2", "ucs2_hungarian_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 147, 1, "ucs2", "ucs2_sinhala_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2},
  { 149, 1, "ucs2", "ucs2_croatian_ci", "", "", 2, 2, mysql_mbcharlen_ucs2, check_mb_ucs2}, /* MDB */

  { 192, 1, UTF8_MB3, UTF8_MB3"_general_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 193, 1, UTF8_MB3, UTF8_MB3"_icelandic_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 194, 1, UTF8_MB3, UTF8_MB3"_latvian_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3,  check_mb_utf8mb3_valid},
  { 195, 1, UTF8_MB3, UTF8_MB3"_romanian_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 196, 1, UTF8_MB3, UTF8_MB3"_slovenian_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 197, 1, UTF8_MB3, UTF8_MB3"_polish_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 198, 1, UTF8_MB3, UTF8_MB3"_estonian_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 119, 1, UTF8_MB3, UTF8_MB3"_spanish_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 200, 1, UTF8_MB3, UTF8_MB3"_swedish_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 201, 1, UTF8_MB3, UTF8_MB3"_turkish_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 202, 1, UTF8_MB3, UTF8_MB3"_czech_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 203, 1, UTF8_MB3, UTF8_MB3"_danish_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid },
  { 204, 1, UTF8_MB3, UTF8_MB3"_lithunian_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid },
  { 205, 1, UTF8_MB3, UTF8_MB3"_slovak_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 206, 1, UTF8_MB3, UTF8_MB3"_spanish2_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 207, 1, UTF8_MB3, UTF8_MB3"_roman_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 208, 1, UTF8_MB3, UTF8_MB3"_persian_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 209, 1, UTF8_MB3, UTF8_MB3"_esperanto_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 210, 1, UTF8_MB3, UTF8_MB3"_hungarian_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 211, 1, UTF8_MB3, UTF8_MB3"_sinhala_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid},
  { 213, 1, UTF8_MB3, UTF8_MB3"_croatian_ci", "", "", 1, 3, mysql_mbcharlen_utf8mb3, check_mb_utf8mb3_valid}, /*MDB*/

  { 224, 1, UTF8_MB4, UTF8_MB4"_unicode_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 225, 1, UTF8_MB4, UTF8_MB4"_icelandic_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 226, 1, UTF8_MB4, UTF8_MB4"_latvian_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 227, 1, UTF8_MB4, UTF8_MB4"_romanian_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 228, 1, UTF8_MB4, UTF8_MB4"_slovenian_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 229, 1, UTF8_MB4, UTF8_MB4"_polish_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 230, 1, UTF8_MB4, UTF8_MB4"_estonian_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 231, 1, UTF8_MB4, UTF8_MB4"_spanish_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 232, 1, UTF8_MB4, UTF8_MB4"_swedish_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 233, 1, UTF8_MB4, UTF8_MB4"_turkish_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 234, 1, UTF8_MB4, UTF8_MB4"_czech_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 235, 1, UTF8_MB4, UTF8_MB4"_danish_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 236, 1, UTF8_MB4, UTF8_MB4"_lithuanian_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 237, 1, UTF8_MB4, UTF8_MB4"_slovak_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 238, 1, UTF8_MB4, UTF8_MB4"_spanish2_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 239, 1, UTF8_MB4, UTF8_MB4"_roman_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 240, 1, UTF8_MB4, UTF8_MB4"_persian_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 241, 1, UTF8_MB4, UTF8_MB4"_esperanto_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 242, 1, UTF8_MB4, UTF8_MB4"_hungarian_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  { 243, 1, UTF8_MB4, UTF8_MB4"_sinhala_ci", "", "", 1, 4, mysql_mbcharlen_utf8, check_mb_utf8_valid},

  { 254, 1, UTF8_MB3, UTF8_MB3"_general_cs", "", "", 1, 3, mysql_mbcharlen_utf8, check_mb_utf8_valid},
  {   0, 0, NULL, NULL, NULL, NULL, 0, 0, NULL, NULL}
};
/* }}} */


/* {{{ mysql_find_charset_nr */
const CHARSET_INFO * mysql_find_charset_nr(unsigned int charsetnr)
{
  const CHARSET_INFO * c = compiled_charsets;
  DBUG_ENTER("mysql_find_charset_nr");

  do {
    if (c->nr == charsetnr) {
      DBUG_PRINT("info", ("found character set %d %s", c->nr, c->csname));
      DBUG_RETURN(c);
    }
    ++c;
  } while (c[0].nr != 0);
  DBUG_RETURN(NULL);
}
/* }}} */


/* {{{ mysql_find_charset_name */
CHARSET_INFO * mysql_find_charset_name(const char *name)
{
  CHARSET_INFO *c = (CHARSET_INFO *)compiled_charsets;
  DBUG_ENTER("mysql_find_charset_nr");

  do {
    if (!strcasecmp(c->csname, name)) {
      DBUG_PRINT("info", ("found character set %d %s", c->nr, c->csname));
      DBUG_RETURN(c);
    }
    ++c;
  } while (c[0].nr != 0);
  return NULL;
}
/* }}} */


/* {{{ mysql_cset_escape_quotes */
size_t mysql_cset_escape_quotes(const CHARSET_INFO *cset, char *newstr,
                    const char * escapestr, size_t escapestr_len )
{
  const char   *newstr_s = newstr;
  const char   *newstr_e = newstr + 2 * escapestr_len;
  const char   *end = escapestr + escapestr_len;
  my_bool  escape_overflow = FALSE;

  DBUG_ENTER("mysql_cset_escape_quotes");

  for (;escapestr < end; escapestr++) {
    unsigned int len = 0;
    /* check unicode characters */

    if (cset->char_maxlen > 1 && (len = cset->mb_valid(escapestr, end))) {

      /* check possible overflow */
      if ((newstr + len) > newstr_e) {
        escape_overflow = TRUE;
        break;
      }
      /* copy mb char without escaping it */
      while (len--) {
        *newstr++ = *escapestr++;
      }
      escapestr--;
      continue;
    }
    if (*escapestr == '\'') {
      if (newstr + 2 > newstr_e) {
        escape_overflow = TRUE;
        break;
      }
      *newstr++ = '\'';
      *newstr++ = '\'';
    } else {
      if (newstr + 1 > newstr_e) {
        escape_overflow = TRUE;
        break;
      }
      *newstr++ = *escapestr;
    }
  }
  *newstr = '\0';

  if (escape_overflow) {
    DBUG_RETURN((size_t)~0);
  }
  DBUG_RETURN((size_t)(newstr - newstr_s));
}
/* }}} */


/* {{{ mysql_cset_escape_slashes */
size_t mysql_cset_escape_slashes(const CHARSET_INFO * cset, char *newstr,
                     const char * escapestr, size_t escapestr_len )
{
  const char   *newstr_s = newstr;
  const char   *newstr_e = newstr + 2 * escapestr_len;
  const char   *end = escapestr + escapestr_len;
  my_bool  escape_overflow = FALSE;

  DBUG_ENTER("mysql_cset_escape_slashes");
  DBUG_PRINT("info", ("charset=%s", cset->name));

  for (;escapestr < end; escapestr++) {
    char esc = '\0';
    unsigned int len = 0;

    /* check unicode characters */
    if (cset->char_maxlen > 1 && (len = cset->mb_valid(escapestr, end))) {
      /* check possible overflow */
      if ((newstr + len) > newstr_e) {
        escape_overflow = TRUE;
        break;
      }
      /* copy mb char without escaping it */
      while (len--) {
        *newstr++ = *escapestr++;
      }
      escapestr--;
      continue;
    }
    if (cset->char_maxlen > 1 && cset->mb_charlen(*escapestr) > 1) {
      esc = *escapestr;
    } else {
      switch (*escapestr) {
        case 0:
          esc = '0';
          break;
        case '\n':
          esc = 'n';
          break;
        case '\r':
          esc = 'r';
          break;
        case '\\':
        case '\'':
        case '"':
          esc = *escapestr;
          break;
        case '\032':
          esc = 'Z';
          break;
      }
    }
    if (esc) {
      if (newstr + 2 > newstr_e) {
        escape_overflow = TRUE;
        break;
      }
      /* copy escaped character */
      *newstr++ = '\\';
      *newstr++ = esc;
    } else {
      if (newstr + 1 > newstr_e) {
        escape_overflow = TRUE;
        break;
      }
      /* copy non escaped character */
      *newstr++ = *escapestr;
    }
  }
  *newstr = '\0';

  if (escape_overflow) {
    DBUG_RETURN((size_t)~0);
  }
  DBUG_RETURN((size_t)(newstr - newstr_s));
}
/* }}} */
