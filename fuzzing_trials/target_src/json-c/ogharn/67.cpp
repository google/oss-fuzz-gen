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

extern "C" int LLVMFuzzerTestOneInput_67(char *fuzzData, size_t size)
{
	

   struct json_object* json_object_new_objectval1 = json_object_new_object();
	if(!json_object_new_objectval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_object_add_exval1 = json_object_object_add_ex(json_object_new_objectval1, fuzzData, NULL, size);
	if((int)json_object_object_add_exval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_object_addval1 = json_object_object_add(json_object_new_objectval1, fuzzData, NULL);
	if((int)json_object_object_addval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
