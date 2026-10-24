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

extern "C" int LLVMFuzzerTestOneInput_70(char *fuzzData, size_t size)
{
	

   CURLU* curl_urlval1 = curl_url();
	if(!curl_urlval1){
		fprintf(stderr, "err");
		exit(0);	}
   CURLUcode curl_url_setval1 = curl_url_set(curl_urlval1, CURLUPART_PASSWORD, fuzzData, size);
	if(curl_url_setval1 != CURLUE_OK){
		fprintf(stderr, "err");
		exit(0);	}
   CURLU* curl_url_dupval1 = curl_url_dup(curl_urlval1);
	if(!curl_url_dupval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
