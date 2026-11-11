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

extern "C" int LLVMFuzzerTestOneInput_11(char *fuzzData, size_t size)
{
	

   size_t array_list_del_idxvar1 = 1;
   size_t array_list_del_idxvar2 = 1;
   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_to_fdval1 = json_object_to_fd(JSON_C_OPTION_THREAD, json_tokener_parseval1, JSON_C_TO_STRING_PRETTY);
	if((int)json_object_to_fdval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   struct array_list* json_object_get_arrayval1 = json_object_get_array(json_tokener_parseval1);
	if(!json_object_get_arrayval1){
		fprintf(stderr, "err");
		exit(0);	}
   int array_list_del_idxval1 = array_list_del_idx(json_object_get_arrayval1, array_list_del_idxvar1, array_list_del_idxvar2);
	if((int)array_list_del_idxval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
