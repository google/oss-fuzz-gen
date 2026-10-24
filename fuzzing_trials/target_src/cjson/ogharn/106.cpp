#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <cJSON.h>

extern "C" int LLVMFuzzerTestOneInput_106(char *fuzzData, size_t size)
{
	

   cJSON cJSON_AddItemToObjectCSvar2;
	memset(&cJSON_AddItemToObjectCSvar2, 0, sizeof(cJSON_AddItemToObjectCSvar2));

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
   cJSON_bool cJSON_AddItemToObjectCSval1 = cJSON_AddItemToObjectCS(cJSON_ParseWithOptsval1, fuzzData, &cJSON_AddItemToObjectCSvar2);
	if(cJSON_AddItemToObjectCSval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON* cJSON_GetObjectItemval1 = cJSON_GetObjectItem(cJSON_ParseWithOptsval1, fuzzData);
	if(!cJSON_GetObjectItemval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
