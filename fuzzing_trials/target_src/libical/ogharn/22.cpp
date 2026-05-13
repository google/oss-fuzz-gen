#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_22(char *fuzzData, size_t size)
{
	
        
   icalcomponent_kind ICAL_VEVENT_COMPONENTVAL = ICAL_VEVENT_COMPONENT;

   struct icaldurationtype icalcomponent_set_durationvar0;
	memset(&icalcomponent_set_durationvar0, 0, (sizeof icalcomponent_set_durationvar0));

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_normalize(icalcomponent_new_from_stringval1);
   icalcomponent_set_duration(icalcomponent_new_from_stringval1, icalcomponent_set_durationvar0);
   icalcomponent* icalcomponent_get_first_componentval1 = icalcomponent_get_first_component(icalcomponent_new_from_stringval1, ICAL_VEVENT_COMPONENTVAL);
	if(!icalcomponent_get_first_componentval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
