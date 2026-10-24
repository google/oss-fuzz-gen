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

extern "C" int LLVMFuzzerTestOneInput_19(char *fuzzData, size_t size)
{
	

   struct printbuf json_object_double_to_json_stringvar1;
	memset(&json_object_double_to_json_stringvar1, 0, sizeof(json_object_double_to_json_stringvar1));

   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_to_fdval1 = json_object_to_fd(JSON_C_OPTION_THREAD, json_tokener_parseval1, JSON_C_TO_STRING_PRETTY);
	if((int)json_object_to_fdval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   struct json_object* json_object_new_intval1 = json_object_new_int(json_object_to_fdval1);
	if(!json_object_new_intval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_double_to_json_stringval1 = json_object_double_to_json_string(json_object_new_intval1, &json_object_double_to_json_stringvar1, JSON_C_STR_HASH_DFLT, JSON_C_TO_STRING_COLOR);
	if((int)json_object_double_to_json_stringval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
