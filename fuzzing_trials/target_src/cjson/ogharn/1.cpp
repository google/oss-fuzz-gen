#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <cJSON.h>

extern "C" int LLVMFuzzerTestOneInput_1(char *fuzzData, size_t size)
{
	

   char* cJSON_Versionval1 = (char*)cJSON_Version();
	if(!cJSON_Versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON* cJSON_ParseWithOptsval1 = cJSON_ParseWithOpts(fuzzData, (const char **)&cJSON_Versionval1, strlen((const char*)cJSON_Versionval1));
	if(!cJSON_ParseWithOptsval1){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON_bool cJSON_ReplaceItemInArrayval1 = cJSON_ReplaceItemInArray(cJSON_ParseWithOptsval1, 1, cJSON_ParseWithOptsval1);
	if(cJSON_ReplaceItemInArrayval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON* cJSON_DetachItemFromArrayval1 = cJSON_DetachItemFromArray(cJSON_ParseWithOptsval1, cJSON_ReplaceItemInArrayval1);
	if(!cJSON_DetachItemFromArrayval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* cJSON_Printval1 = cJSON_Print(cJSON_DetachItemFromArrayval1);
	if(!cJSON_Printval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
