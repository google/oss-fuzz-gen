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

extern "C" int LLVMFuzzerTestOneInput_45(char *fuzzData, size_t size)
{
	

   char** curl_url_getvar2[size+1];
	sprintf((char *)curl_url_getvar2, "/tmp/xeat9");
   CURLU* curl_urlval1 = curl_url();
	if(!curl_urlval1){
		fprintf(stderr, "err");
		exit(0);	}
   CURLUcode curl_url_setval1 = curl_url_set(curl_urlval1, CURLUPART_PASSWORD, fuzzData, size);
	if(curl_url_setval1 != CURLUE_OK){
		fprintf(stderr, "err");
		exit(0);	}
   CURLUcode curl_url_getval1 = curl_url_get(curl_urlval1, CURLUPART_PASSWORD, (char **)curl_url_getvar2, sizeof(curl_url_getvar2));
	if(curl_url_getval1 != CURLUE_OK){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
