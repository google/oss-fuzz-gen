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

extern "C" int LLVMFuzzerTestOneInput_33(char *fuzzData, size_t size)
{
	

   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   const char* json_object_to_json_stringval1 = json_object_to_json_string(json_tokener_parseval1);
	if(!json_object_to_json_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
