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

extern "C" int LLVMFuzzerTestOneInput_39(char *fuzzData, size_t size)
{
	

   CURLUPart curl_url_setvar1;
	memset(&curl_url_setvar1, 0, sizeof(curl_url_setvar1));

   int curl_easy_unescapevar3 = 1;
   CURLU* curl_urlval1 = curl_url();
	if(!curl_urlval1){
		fprintf(stderr, "err");
		exit(0);	}
   CURLUcode curl_url_setval1 = curl_url_set(curl_urlval1, CURLUPART_FRAGMENT, fuzzData, size);
	if(curl_url_setval1 != CURLUE_OK){
		fprintf(stderr, "err");
		exit(0);	}
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   CURLUcode curl_url_getval1 = curl_url_get(curl_urlval1, CURLUPART_FRAGMENT, &fuzzData, size);
	if(curl_url_getval1 != CURLUE_OK){
		fprintf(stderr, "err");
		exit(0);	}
   CURLU* curl_urlval2 = curl_url();
	if(!curl_urlval2){
		fprintf(stderr, "err");
		exit(0);	}
   CURLUcode curl_url_setval2 = curl_url_set(curl_urlval1, curl_url_setvar1, fuzzData, CURLOPT_PROGRESSDATA);
	if(curl_url_setval2 != CURLUE_OK){
		fprintf(stderr, "err");
		exit(0);	}
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   CURLUcode curl_url_getval2 = curl_url_get(curl_urlval1, CURLUPART_URL, &fuzzData, size);
	if(curl_url_getval2 != CURLUE_OK){
		fprintf(stderr, "err");
		exit(0);	}
   CURL* curl_easy_initval1 = curl_easy_init();
	if(!curl_easy_initval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* curl_easy_unescapeval1 = curl_easy_unescape(curl_easy_initval1, fuzzData, size, &curl_easy_unescapevar3);
	if(!curl_easy_unescapeval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
