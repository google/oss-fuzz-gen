#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <arraylist.h>
#include <json_object.h>
#include <json_object_iterator.h>
#include <json_tokener.h>
#include <json_util.h>
#include <linkhash.h>

extern "C" int LLVMFuzzerTestOneInput_68(char *fuzzData, size_t size)
{
	

   char* json_object_to_file_extvar0[size+1];
	sprintf((char *)json_object_to_file_extvar0, "/tmp/e1z0r");
   char* json_object_object_delvar1[size+1];
	sprintf((char *)json_object_object_delvar1, "/tmp/0rbcd");
   struct json_object* json_object_new_objectval1 = json_object_new_object();
	if(!json_object_new_objectval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_object_add_exval1 = json_object_object_add_ex(json_object_new_objectval1, fuzzData, NULL, size);
	if((int)json_object_object_add_exval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_to_file_extval1 = json_object_to_file_ext((const char*)json_object_to_file_extvar0, json_object_new_objectval1, sizeof(json_object_to_file_extvar0));
	if((int)json_object_to_file_extval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   json_object_object_del(json_object_new_objectval1, (const char *)json_object_object_delvar1);
   return 0;
}
