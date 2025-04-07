#include "json.h"
#include "test.h"

int main(void)
{
	json::jobject obj1;
	obj1["key1"] = "value1";
	json::jobject obj2;
	obj2["key2"] = "value2";

	obj1 += obj2;

	TEST_EQUAL(obj1.size(), 2);
	TEST_TRUE(obj1.has_key("key1"));
	TEST_STRING_EQUAL(obj1["key1"].as_string().c_str(), "value1");
	TEST_TRUE(obj1.has_key("key2"));
	TEST_STRING_EQUAL(obj1["key2"].as_string().c_str(), "value2");

	json::jobject obj3;
	obj3["key3"] = "value3";

	json::jobject obj4 = obj1 + obj3;
	TEST_EQUAL(obj4.size(), 3);
	TEST_TRUE(obj4.has_key("key1"));
	TEST_STRING_EQUAL(obj4["key1"].as_string().c_str(), "value1");
	TEST_TRUE(obj4.has_key("key2"));
	TEST_STRING_EQUAL(obj4["key2"].as_string().c_str(), "value2");
	TEST_TRUE(obj4.has_key("key3"));
	TEST_STRING_EQUAL(obj4["key3"].as_string().c_str(), "value3");
}