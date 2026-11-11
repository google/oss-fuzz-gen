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

static void function_pointer3458764515962781696fp(json_object*, void*){
	exit(0);
}
extern "C" int LLVMFuzzerTestOneInput_10(char *fuzzData, size_t size)
{
	

   char* json_object_to_file_extvar0[size+1];
	sprintf((char *)json_object_to_file_extvar0, "/tmp/y2bwi");
   void* json_object_set_userdatavar1[size+1];
	sprintf((char *)json_object_set_userdatavar1, "/tmp/rcc69");
   struct array_list array_list_put_idxvar0;
	memset(&array_list_put_idxvar0, 0, sizeof(array_list_put_idxvar0));

   size_t array_list_put_idxvar1 = 1;
   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   int json_object_to_file_extval1 = json_object_to_file_ext((const char*)json_object_to_file_extvar0, json_tokener_parseval1, sizeof(json_object_to_file_extvar0));
	if((int)json_object_to_file_extval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   json_object_set_userdata(json_tokener_parseval1, json_object_set_userdatavar1, function_pointer3458764515962781696fp);
   int array_list_put_idxval1 = array_list_put_idx(&array_list_put_idxvar0, array_list_put_idxvar1, (void*)json_object_set_userdatavar1);
	if((int)array_list_put_idxval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
