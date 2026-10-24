#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <curl.h>
#include <easy.h>
#include <urlapi.h>
#include <header.h>
#include <multi.h>
#include <options.h>
#include <websockets.h>

extern "C" int LLVMFuzzerTestOneInput_44(char *fuzzData, size_t size)
{
	

   time_t curl_getdatevartime_tsize = size;
   time_t curl_getdateval1 = curl_getdate(fuzzData, &curl_getdatevartime_tsize);
   return 0;
}
