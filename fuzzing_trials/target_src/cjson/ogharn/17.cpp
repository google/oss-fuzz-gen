#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <cJSON.h>

extern "C" int LLVMFuzzerTestOneInput_17(char *fuzzData, size_t size)
{
	

   char* cJSON_Versionval1 = (char*)cJSON_Version();
	if(!cJSON_Versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON* cJSON_ParseWithOptsval1 = cJSON_ParseWithOpts(fuzzData, (const char **)&cJSON_Versionval1, strlen((const char *)&cJSON_Versionval1));
	if(!cJSON_ParseWithOptsval1){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON* cJSON_Duplicateval1 = cJSON_Duplicate(cJSON_ParseWithOptsval1, 1);
	if(!cJSON_Duplicateval1){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON_bool cJSON_ReplaceItemInArrayval1 = cJSON_ReplaceItemInArray(cJSON_Duplicateval1, 0, cJSON_Duplicateval1);
	if(cJSON_ReplaceItemInArrayval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON* cJSON_DetachItemViaPointerval1 = cJSON_DetachItemViaPointer(cJSON_Duplicateval1, cJSON_Duplicateval1);
	if(!cJSON_DetachItemViaPointerval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
