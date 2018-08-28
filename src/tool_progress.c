/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "tool_setup.h"
#include "tool_operate.h"
#include "tool_progress.h"
#include "tool_util.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

/* The point of this function would be to return a string of the input data,
   but never longer than 5 columns (+ one zero byte).
   Add suffix k, M, G when suitable... */
static char *max5data(curl_off_t bytes, char *max5)
{
#define ONE_KILOBYTE  CURL_OFF_T_C(1024)
#define ONE_MEGABYTE (CURL_OFF_T_C(1024) * ONE_KILOBYTE)
#define ONE_GIGABYTE (CURL_OFF_T_C(1024) * ONE_MEGABYTE)
#define ONE_TERABYTE (CURL_OFF_T_C(1024) * ONE_GIGABYTE)
#define ONE_PETABYTE (CURL_OFF_T_C(1024) * ONE_TERABYTE)

  if(bytes < CURL_OFF_T_C(100000))
    msnprintf(max5, 6, "%5" CURL_FORMAT_CURL_OFF_T, bytes);

  else if(bytes < CURL_OFF_T_C(10000) * ONE_KILOBYTE)
    msnprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "k", bytes/ONE_KILOBYTE);

  else if(bytes < CURL_OFF_T_C(100) * ONE_MEGABYTE)
    /* 'XX.XM' is good as long as we're less than 100 megs */
    msnprintf(max5, 6, "%2" CURL_FORMAT_CURL_OFF_T ".%0"
              CURL_FORMAT_CURL_OFF_T "M", bytes/ONE_MEGABYTE,
              (bytes%ONE_MEGABYTE) / (ONE_MEGABYTE/CURL_OFF_T_C(10)) );

#if (CURL_SIZEOF_CURL_OFF_T > 4)

  else if(bytes < CURL_OFF_T_C(10000) * ONE_MEGABYTE)
    /* 'XXXXM' is good until we're at 10000MB or above */
    msnprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "M", bytes/ONE_MEGABYTE);

  else if(bytes < CURL_OFF_T_C(100) * ONE_GIGABYTE)
    /* 10000 MB - 100 GB, we show it as XX.XG */
    msnprintf(max5, 6, "%2" CURL_FORMAT_CURL_OFF_T ".%0"
              CURL_FORMAT_CURL_OFF_T "G", bytes/ONE_GIGABYTE,
              (bytes%ONE_GIGABYTE) / (ONE_GIGABYTE/CURL_OFF_T_C(10)) );

  else if(bytes < CURL_OFF_T_C(10000) * ONE_GIGABYTE)
    /* up to 10000GB, display without decimal: XXXXG */
    msnprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "G", bytes/ONE_GIGABYTE);

  else if(bytes < CURL_OFF_T_C(10000) * ONE_TERABYTE)
    /* up to 10000TB, display without decimal: XXXXT */
    msnprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "T", bytes/ONE_TERABYTE);

  else
    /* up to 10000PB, display without decimal: XXXXP */
    msnprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "P", bytes/ONE_PETABYTE);

    /* 16384 petabytes (16 exabytes) is the maximum a 64 bit unsigned number
       can hold, but our data type is signed so 8192PB will be the maximum. */

#else

  else
    msnprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "M", bytes/ONE_MEGABYTE);

#endif

  return max5;
}

static curl_off_t all_dlnow;
static curl_off_t all_ulnow;

int xferinfo_cb(void *clientp,
                curl_off_t dltotal,
                curl_off_t dlnow,
                curl_off_t ultotal,
                curl_off_t ulnow)
{
  struct per_transfer *per = clientp;
  (void)dltotal;
  (void)ultotal;

  all_dlnow += dlnow;
  all_dlnow -= per->prev_dlnow;
  per->prev_dlnow = dlnow;

  all_ulnow += ulnow;
  all_ulnow -= per->prev_ulnow;
  per->prev_ulnow = ulnow;

  return 0;
}

bool progress_meter(struct GlobalConfig *global,
                    struct timeval *start,
                    bool final)
{
  struct timeval now = tvnow();
  char buffer[6];

  if(final || (tvdiff(now, *start) >= 1000)) {
    fprintf(global->errors,
            "\r"
            "%s%s", max5data(all_dlnow, buffer),
            final ? "\n" :"");
    return TRUE;
  }
  return FALSE;
}

