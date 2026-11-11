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

extern "C" int LLVMFuzzerTestOneInput_24(char *fuzzData, size_t size)
{
	

   CURLsslset curl_global_sslsetval1 = curl_global_sslset(CURLSSLBACKEND_OPENSSL, fuzzData, NULL);
	if(curl_global_sslsetval1 != CURLSSLSET_OK){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
