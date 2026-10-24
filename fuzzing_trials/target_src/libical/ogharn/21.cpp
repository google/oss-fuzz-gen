#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_21(char *fuzzData, size_t size)
{
	
        

   struct icaldurationtype icalcomponent_set_durationvar0;
	memset(&icalcomponent_set_durationvar0, 0, (sizeof icalcomponent_set_durationvar0));

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_normalize(icalcomponent_new_from_stringval1);
   icalcomponent_set_duration(icalcomponent_new_from_stringval1, icalcomponent_set_durationvar0);
   struct icaltimetype icalproperty_get_datetime_with_componentval1 = icalproperty_get_datetime_with_component(NULL, icalcomponent_new_from_stringval1);
   return 0;
}
