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

extern "C" int LLVMFuzzerTestOneInput_11(char *fuzzData, size_t size)
{
	

   time_t curl_getdatevartime_tsize = size;
   CURLUPart curl_url_setvar1;
	memset(&curl_url_setvar1, 0, sizeof(curl_url_setvar1));

   char* curl_easy_unescapevar1[size+1];
	sprintf((char *)curl_easy_unescapevar1, "/tmp/achg4");
   int curl_easy_unescapevar3 = 1;
   int curl_multi_pollvar3 = 1;
   time_t curl_getdateval1 = curl_getdate(fuzzData, &curl_getdatevartime_tsize);
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
   int curl_strnequalval1 = curl_strnequal(fuzzData, NULL, sizeof(NULL));
	if((int)curl_strnequalval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   CURLM* curl_multi_initval1 = curl_multi_init();
	if(!curl_multi_initval1){
		fprintf(stderr, "err");
		exit(0);	}
   CURLMcode curl_multi_get_offtval1 = curl_multi_get_offt(curl_multi_initval1, CURLMINFO_XFERS_RUNNING, &curl_getdateval1);
	if(curl_multi_get_offtval1 != CURLM_OK){
		fprintf(stderr, "err");
		exit(0);	}
   char* curl_easy_unescapeval1 = curl_easy_unescape((void*)curl_multi_initval1, (char *)curl_easy_unescapevar1, sizeof(curl_easy_unescapevar1), &curl_easy_unescapevar3);
	if(!curl_easy_unescapeval1){
		fprintf(stderr, "err");
		exit(0);	}
   CURLMcode curl_multi_pollval1 = curl_multi_poll((void*)curl_multi_initval1, NULL, curl_strnequalval1, curl_multi_pollvar3, NULL);
	if(curl_multi_pollval1 != CURLM_OK){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
