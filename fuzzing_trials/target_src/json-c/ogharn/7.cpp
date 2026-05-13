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

extern "C" int LLVMFuzzerTestOneInput_7(char *fuzzData, size_t size)
{
	

   struct json_tokener* json_tokener_newval1 = json_tokener_new();
	if(!json_tokener_newval1){
		fprintf(stderr, "err");
		exit(0);	}
   struct json_object* json_tokener_parse_exval1 = json_tokener_parse_ex(json_tokener_newval1, fuzzData, size);
	if(!json_tokener_parse_exval1){
		fprintf(stderr, "err");
		exit(0);	}
   json_tokener_reset(json_tokener_newval1);
   size_t json_tokener_get_parse_endval1 = json_tokener_get_parse_end(json_tokener_newval1);
	if((int)json_tokener_get_parse_endval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   struct json_object* json_object_new_uint64val1 = json_object_new_uint64(json_tokener_get_parse_endval1);
	if(!json_object_new_uint64val1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
