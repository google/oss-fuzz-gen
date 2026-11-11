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

extern "C" int LLVMFuzzerTestOneInput_60(char *fuzzData, size_t size)
{
	

   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_putval1 = json_object_put(json_tokener_parseval1);
	if((int)json_object_putval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   struct lh_table* lh_table_newval1 = lh_table_new(json_object_putval1, NULL, NULL, NULL);
	if(!lh_table_newval1){
		fprintf(stderr, "err");
		exit(0);	}
   int lh_table_lengthval1 = lh_table_length(lh_table_newval1);
	if((int)lh_table_lengthval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
