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

extern "C" int LLVMFuzzerTestOneInput_7(char *fuzzData, size_t size)
{
	

   time_t curl_getdatevar1;
	memset(&curl_getdatevar1, 0, sizeof(curl_getdatevar1));

   CURL* curl_easy_initval1 = curl_easy_init();
	if(!curl_easy_initval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* curl_easy_escapeval1 = curl_easy_escape(curl_easy_initval1, fuzzData, CURL_VERSION_NTLM_WB);
	if(!curl_easy_escapeval1){
		fprintf(stderr, "err");
		exit(0);	}
   time_t curl_getdateval1 = curl_getdate(curl_easy_escapeval1, &curl_getdatevar1);
   return 0;
}
