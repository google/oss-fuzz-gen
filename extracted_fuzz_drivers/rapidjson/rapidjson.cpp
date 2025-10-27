#include <fuzzing/testers/serialize/json.hpp>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

class RapidjsonJsonManipulator : public fuzzing::testers::serialize::JsonManipulator<rapidjson::Value> {
public:
  RapidjsonJsonManipulator(void) : fuzzing::testers::serialize::JsonManipulator<rapidjson::Value>() {}
  ~RapidjsonJsonManipulator() override = default;

  /* Conversion */
  std::optional<rapidjson::Value> StringToObject(const std::string &input) override {
    rapidjson::Document document;

    rapidjson::ParseResult pr = document.Parse(input.c_str());
    if (!pr) {
      return std::nullopt;
    }

    rapidjson::Value value;
    value.CopyFrom(document, document.GetAllocator());
    return value;
  }

  std::optional<std::string> ObjectToString(const rapidjson::Value &input) override {
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);
    input.Accept(writer);
    return sb.GetString();
  }

  /* Introspection */
  std::optional<bool> IsEqual(const rapidjson::Value &input1, const rapidjson::Value &input2) override { return input1 == input2; }

  std::optional<bool> IsNotEqual(const rapidjson::Value &input1, const rapidjson::Value &input2) override { return input1 != input2; }

  std::optional<bool> IsObject(const rapidjson::Value &input) override { return input.IsObject(); }

  std::optional<bool> IsArray(const rapidjson::Value &input) override { return input.IsArray(); }

  std::optional<bool> IsString(const rapidjson::Value &input) override { return input.IsString(); }

  std::optional<bool> IsNumber(const rapidjson::Value &input) override { return input.IsNumber(); }

  std::optional<bool> IsBoolean(const rapidjson::Value &input) override { return input.IsBool(); }

  std::optional<std::vector<std::string>> GetMemberNames(const rapidjson::Value &input) override {
    std::vector<std::string> ret;

    for (auto it = input.MemberBegin(); it < input.MemberEnd(); it++) {
      ret.push_back(it->name.GetString());
    }

    return ret;
  }

  std::optional<uint64_t> GetArraySize(const rapidjson::Value &input) override { return input.Size(); }

  std::optional<double> GetDouble(rapidjson::Value &input) override { return input.GetDouble(); }

  std::optional<int32_t> GetInt32(rapidjson::Value &input) override {
    static_assert(sizeof(int32_t) == sizeof(int));
    return input.GetInt();
  }

  std::optional<int64_t> GetInt64(rapidjson::Value &input) override { return input.GetInt64(); }

  std::optional<bool> HasMember(const rapidjson::Value &input, const std::string name) override { return input.HasMember(name.c_str()); }

  rapidjson::Value &GetMemberReference(rapidjson::Value &input, const std::string name) override {
    rapidjson::Value::MemberIterator itr = input.FindMember(name.c_str());
    return itr->value;
  }

  rapidjson::Value &GetMemberReference(rapidjson::Value &input, const uint64_t index) override { return input[index]; }

  /* CRUD */
  std::optional<rapidjson::Value> Copy(const rapidjson::Value &input) override {
    rapidjson::Document d;
    rapidjson::Value value(input, d.GetAllocator());
    return value;
  }

  bool SetKey(rapidjson::Value &dest, const std::string key) override {
    dest[key.c_str()] = {};

    return true;
  }

  bool SetDouble(rapidjson::Value &dest, const double val) override {
    dest.SetDouble(val);

    return true;
  }

  bool SetInt32(rapidjson::Value &dest, const int32_t val) override {
    static_assert(sizeof(int32_t) == sizeof(int));
    dest.SetInt(val);

    return true;
  }

  bool SetInt64(rapidjson::Value &dest, const int64_t val) override {
    dest.SetInt64(val);

    return true;
  }

  bool Swap(rapidjson::Value &input1, rapidjson::Value &input2) override {
    input1.Swap(input2);

    return true;
  }

  bool Clear(rapidjson::Value &input) override {
    input = {};

    return true;
  }

  bool Set(rapidjson::Value &input1, const rapidjson::Value &input2) override {
    /* Crashes */
#if 0
            rapidjson::Document d;
            input1.CopyFrom(input2, d.GetAllocator());
            return true;
#else
    return false;
#endif
  }
};

std::unique_ptr<fuzzing::testers::serialize::JsonTester<rapidjson::Value, false>> jsonTester;

extern "C" int LLVMFuzzerInitialize(int *_argc, char ***_argv) {
  (void)_argc;
  (void)_argv;

  jsonTester = std::make_unique<fuzzing::testers::serialize::JsonTester<rapidjson::Value, false>>(std::make_unique<RapidjsonJsonManipulator>());

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzzing::datasource::Datasource ds(data, size);

  try {
    jsonTester->Test(ds);
  } catch (fuzzing::datasource::Datasource::OutOfData) {
  }

  return 0;
}
