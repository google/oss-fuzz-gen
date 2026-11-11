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

extern "C" int LLVMFuzzerTestOneInput_62(char *fuzzData, size_t size)
{
	

   char* json_object_object_get_exvar1[size+1];
	sprintf((char *)json_object_object_get_exvar1, "/tmp/l4maq");
   json_type json_object_is_typevar1;
	memset(&json_object_is_typevar1, 0, sizeof(json_object_is_typevar1));

   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_object_get_exval1 = json_object_object_get_ex(json_tokener_parseval1, (const char *) json_object_object_get_exvar1, &json_tokener_parseval1);
	if((int)json_object_object_get_exval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_is_typeval1 = json_object_is_type(json_tokener_parseval1, json_object_is_typevar1);
	if((int)json_object_is_typeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
