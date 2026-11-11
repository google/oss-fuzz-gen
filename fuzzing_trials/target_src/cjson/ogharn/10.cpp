#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <cJSON.h>

extern "C" int LLVMFuzzerTestOneInput_10(char *fuzzData, size_t size)
{
	

   char* cJSON_Versionval1 = (char*)cJSON_Version();
	if(!cJSON_Versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON* cJSON_ParseWithOptsval1 = cJSON_ParseWithOpts(fuzzData, (const char **)&cJSON_Versionval1, strlen((const char *)&cJSON_Versionval1));
	if(!cJSON_ParseWithOptsval1){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON_bool cJSON_PrintPreallocatedval1 = cJSON_PrintPreallocated(cJSON_ParseWithOptsval1, cJSON_Versionval1, strlen(cJSON_Versionval1), 1);
	if(cJSON_PrintPreallocatedval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   cJSON* cJSON_AddBoolToObjectval1 = cJSON_AddBoolToObject(cJSON_ParseWithOptsval1, cJSON_Versionval1, strlen(cJSON_Versionval1));
	if(!cJSON_AddBoolToObjectval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
