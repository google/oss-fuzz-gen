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

extern "C" int LLVMFuzzerTestOneInput_25(char *fuzzData, size_t size)
{
	

   int64_t json_object_int_incvar1;
	memset(&json_object_int_incvar1, 0, sizeof(json_object_int_incvar1));

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
   int json_object_int_incval1 = json_object_int_inc(json_tokener_parseval1, json_object_int_incvar1);
	if((int)json_object_int_incval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
