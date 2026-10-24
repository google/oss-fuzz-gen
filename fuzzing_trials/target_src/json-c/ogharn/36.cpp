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

extern "C" int LLVMFuzzerTestOneInput_36(char *fuzzData, size_t size)
{
	

   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_to_fdval1 = json_object_to_fd(JSON_C_OPTION_THREAD, json_tokener_parseval1, JSON_C_TO_STRING_PRETTY);
	if((int)json_object_to_fdval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_equalval1 = json_object_equal(json_tokener_parseval1, NULL);
	if((int)json_object_equalval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   const char* json_object_to_json_string_lengthval1 = json_object_to_json_string_length(NULL, json_object_equalval1, NULL);
	if(!json_object_to_json_string_lengthval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
