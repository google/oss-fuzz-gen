#include "json.h"
#include "test.h"
#include <string>

int main(void)
{
	const char *input = " 123457890";
	TEST_STRING_EQUAL(json::parsing::read_digits(input).c_str(), "123457890");
	input = " 123457890a";
	TEST_STRING_EQUAL(json::parsing::read_digits(input).c_str(), "123457890");
}