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

extern "C" int LLVMFuzzerTestOneInput_15(char *fuzzData, size_t size)
{
	

   CURL* curl_easy_initval1 = curl_easy_init();
	if(!curl_easy_initval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* curl_easy_escapeval1 = curl_easy_escape(curl_easy_initval1, fuzzData, CURL_VERSION_NTLM_WB);
	if(!curl_easy_escapeval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* curl_unescapeval1 = curl_unescape(curl_easy_escapeval1, CURLU_NO_AUTHORITY);
	if(!curl_unescapeval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
