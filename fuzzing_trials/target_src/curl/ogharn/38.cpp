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

extern "C" int LLVMFuzzerTestOneInput_38(char *fuzzData, size_t size)
{
	

   char* curl_versionval1 = curl_version();
	if(!curl_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int curl_strnequalval1 = curl_strnequal(NULL, fuzzData, size);
	if((int)curl_strnequalval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
