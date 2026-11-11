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

extern "C" int LLVMFuzzerTestOneInput_28(char *fuzzData, size_t size)
{
	

   CURLUPart curl_url_setvar1;
	memset(&curl_url_setvar1, 0, sizeof(curl_url_setvar1));

   char** curl_url_getvar2[size+1];
	sprintf((char *)curl_url_getvar2, "/tmp/y89du");
   CURLU* curl_urlval1 = curl_url();
	if(!curl_urlval1){
		fprintf(stderr, "err");
		exit(0);	}
   CURLUcode curl_url_setval1 = curl_url_set(curl_urlval1, CURLUPART_QUERY, fuzzData, size);
	if(curl_url_setval1 != CURLUE_OK){
		fprintf(stderr, "err");
		exit(0);	}
   CURLUcode curl_url_getval1 = curl_url_get(curl_urlval1, CURLUPART_QUERY, (char **)curl_url_getvar2, sizeof(curl_url_getvar2));
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
   char* curl_easy_unescapeval1 = curl_easy_unescape(curl_easy_initval1, fuzzData, CURL_MAX_HTTP_HEADER, NULL);
	if(!curl_easy_unescapeval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* curl_unescapeval1 = curl_unescape(curl_easy_unescapeval1, CURL_MAX_HTTP_HEADER);
	if(!curl_unescapeval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
