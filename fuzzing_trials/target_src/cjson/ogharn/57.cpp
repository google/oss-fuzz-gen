#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <cJSON.h>

extern "C" int LLVMFuzzerTestOneInput_57(char *fuzzData, size_t size)
{
	

   char* cJSON_Versionval1 = (char*)cJSON_Version();
	if(!cJSON_Versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON* cJSON_ParseWithOptsval1 = cJSON_ParseWithOpts(fuzzData, (const char **)&cJSON_Versionval1, strlen((const char *)&cJSON_Versionval1));
	if(!cJSON_ParseWithOptsval1){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON_bool cJSON_ReplaceItemInObjectval1 = cJSON_ReplaceItemInObject(cJSON_ParseWithOptsval1, cJSON_Versionval1, cJSON_ParseWithOptsval1);
	if(cJSON_ReplaceItemInObjectval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON* cJSON_AddStringToObjectval1 = cJSON_AddStringToObject(cJSON_ParseWithOptsval1, cJSON_Versionval1, fuzzData);
	if(!cJSON_AddStringToObjectval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* cJSON_GetStringValueval1 = cJSON_GetStringValue(cJSON_AddStringToObjectval1);
	if(!cJSON_GetStringValueval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
