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

extern "C" int LLVMFuzzerTestOneInput_13(char *fuzzData, size_t size)
{
	

   char* json_object_to_file_extvar0[size+1];
	sprintf((char *)json_object_to_file_extvar0, "/tmp/szowi");
   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_to_file_extval1 = json_object_to_file_ext((const char*)json_object_to_file_extvar0, json_tokener_parseval1, sizeof(json_object_to_file_extvar0));
	if((int)json_object_to_file_extval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_set_string_lenval1 = json_object_set_string_len(json_tokener_parseval1, (const char *)json_object_to_file_extvar0, sizeof(json_object_to_file_extvar0));
	if((int)json_object_set_string_lenval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_c_shallow_copy_defaultval1 = json_c_shallow_copy_default(json_tokener_parseval1, NULL, fuzzData, size, &json_tokener_parseval1);
	if((int)json_c_shallow_copy_defaultval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
