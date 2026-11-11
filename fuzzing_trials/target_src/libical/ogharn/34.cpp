#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_34(char *fuzzData, size_t size)
{
	
        

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_normalize(icalcomponent_new_from_stringval1);
   struct icaldurationtype icalcomponent_get_durationval1 = icalcomponent_get_duration(icalcomponent_new_from_stringval1);
   struct icaltimetype icalcomponent_get_recurrenceidval1 = icalcomponent_get_recurrenceid(icalcomponent_new_from_stringval1);
   return 0;
}
