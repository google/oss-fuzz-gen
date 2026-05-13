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
extern "C" int LLVMFuzzerTestOneInput_12(char *fuzzData, size_t size)
{
	

   struct json_object* json_tokener_parseval1 = json_tokener_parse(fuzzData);
	if(!json_tokener_parseval1){
		fprintf(stderr, "err");
		exit(0);	}
   json_object_set_serializer(json_tokener_parseval1, NULL, NULL, function_pointer3458764515962781696fp);
   json_object_set_userdata(json_tokener_parseval1, NULL, NULL);
   return 0;
}
