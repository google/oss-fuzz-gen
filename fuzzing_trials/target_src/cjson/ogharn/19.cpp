#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <cJSON.h>

extern "C" int LLVMFuzzerTestOneInput_19(char *fuzzData, size_t size)
{
	

   cJSON cJSON_Comparevar0;
	memset(&cJSON_Comparevar0, 0, sizeof(cJSON_Comparevar0));

   cJSON cJSON_Comparevar1;
	memset(&cJSON_Comparevar1, 0, sizeof(cJSON_Comparevar1));

   char* cJSON_Versionval1 = (char*)cJSON_Version();
	if(!cJSON_Versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON* cJSON_ParseWithOptsval1 = cJSON_ParseWithOpts(fuzzData, (const char **)&cJSON_Versionval1, strlen((const char *)&cJSON_Versionval1));
	if(!cJSON_ParseWithOptsval1){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON_bool cJSON_ReplaceItemInArrayval1 = cJSON_ReplaceItemInArray(cJSON_ParseWithOptsval1, 1, cJSON_ParseWithOptsval1);
	if(cJSON_ReplaceItemInArrayval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int cJSON_GetArraySizeval1 = cJSON_GetArraySize(cJSON_ParseWithOptsval1);
   cJSON_bool cJSON_Compareval1 = cJSON_Compare(&cJSON_Comparevar0, &cJSON_Comparevar1, cJSON_GetArraySizeval1);
   return 0;
}
