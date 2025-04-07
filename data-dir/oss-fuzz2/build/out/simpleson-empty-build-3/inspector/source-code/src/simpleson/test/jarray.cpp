#include "json.h"
#include "test.h"
#include <math.h>

int main(void)
{
	const char *input =
		"["
			"123.456,"
			"\"hello \\\" world\","
			"[1,2,3],"
			"true,"
			"null,"
			"[{\"key\":\"value\"}],"
			"[\"hello\",\"world\"],"
			"[]"
		"]";

	json::jobject result = json::jobject::parse(input);
	TEST_TRUE(result.is_array())
	TEST_STRING_EQUAL(result.get(0).c_str(), "123.456");
	TEST_STRING_EQUAL(result.get(1).c_str(), "\"hello \\\" world\"");
	TEST_STRING_EQUAL(result.get(2).c_str(), "[1,2,3]");
	TEST_STRING_EQUAL(result.get(3).c_str(), "true");
	TEST_STRING_EQUAL(result.get(4).c_str(), "null");
	TEST_STRING_EQUAL(result.get(5).c_str(), "[{\"key\":\"value\"}]");
	TEST_STRING_EQUAL(result.get(6).c_str(), "[\"hello\",\"world\"]");
	TEST_STRING_EQUAL(result.get(7).c_str(), "[]");

	TEST_TRUE(result.array(3).is_true());
	TEST_TRUE(result.array(4).is_null());
	TEST_TRUE(result.array(5).array(0).as_object() == json::jobject::parse("{\"key\":\"value\"}"));

	// Test serialization
	TEST_STRING_EQUAL(result.as_string().c_str(), input);

	// Test copy constructor
	json::jobject copy(result);
	TEST_STRING_EQUAL(copy.as_string().c_str(), result.as_string().c_str());
}