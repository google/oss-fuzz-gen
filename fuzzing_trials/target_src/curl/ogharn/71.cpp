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

extern "C" int LLVMFuzzerTestOneInput_71(char *fuzzData, size_t size)
{
	

   size_t curl_strnequalvar2 = 1;
   CURLUPart curl_url_setvar1;
	memset(&curl_url_setvar1, 0, sizeof(curl_url_setvar1));

   char* curl_versionval1 = curl_version();
	if(!curl_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int curl_strnequalval1 = curl_strnequal(fuzzData+size, fuzzData, curl_strnequalvar2);
	if((int)curl_strnequalval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   CURLU* curl_urlval1 = curl_url();
	if(!curl_urlval1){
		fprintf(stderr, "err");
		exit(0);	}
   CURLUcode curl_url_setval1 = curl_url_set(curl_urlval1, curl_url_setvar1, fuzzData, CURLOPT_PROGRESSDATA);
	if(curl_url_setval1 != CURLUE_OK){
		fprintf(stderr, "err");
		exit(0);	}
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   CURLUcode curl_url_getval1 = curl_url_get(curl_urlval1, CURLUPART_URL, &fuzzData, size);
	if(curl_url_getval1 != CURLUE_OK){
		fprintf(stderr, "err");
		exit(0);	}
   CURL* curl_easy_initval1 = curl_easy_init();
	if(!curl_easy_initval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* curl_easy_unescapeval1 = curl_easy_unescape(curl_easy_initval1, fuzzData+size, CURLPROXY_HTTP, &curl_strnequalval1);
	if(!curl_easy_unescapeval1){
		fprintf(stderr, "err");
		exit(0);	}
   time_t curl_getdateval1 = curl_getdate(curl_easy_unescapeval1, NULL);
   return 0;
}
