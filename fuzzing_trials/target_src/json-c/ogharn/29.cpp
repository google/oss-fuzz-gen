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

extern "C" int LLVMFuzzerTestOneInput_29(char *fuzzData, size_t size)
{
	

   struct json_object* json_object_deep_copyvar1;
	memset(&json_object_deep_copyvar1, 0, sizeof(json_object_deep_copyvar1));

   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_deep_copyval1 = json_object_deep_copy(json_tokener_parseval1, &json_object_deep_copyvar1, NULL);
	if((int)json_object_deep_copyval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_equalval1 = json_object_equal(json_tokener_parseval1, json_object_deep_copyvar1);
	if((int)json_object_equalval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   struct lh_table* lh_kptr_table_newval1 = lh_kptr_table_new(json_object_equalval1, NULL);
	if(!lh_kptr_table_newval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
