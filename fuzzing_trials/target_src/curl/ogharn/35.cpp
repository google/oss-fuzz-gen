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

extern "C" int LLVMFuzzerTestOneInput_35(char *fuzzData, size_t size)
{
	

   CURLcode curl_global_traceval1 = curl_global_trace(fuzzData);
	if(curl_global_traceval1 != CURLE_OK){
		fprintf(stderr, "err");
		exit(0);	}
   const char* curl_easy_strerrorval1 = curl_easy_strerror(curl_global_traceval1);
	if(!curl_easy_strerrorval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
