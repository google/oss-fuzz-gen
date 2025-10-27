/*
 * A fuzzer focused on the node::LoadEnvironment() function.
 *
 * Code here has been inspired by the cctest test case.
 */

#include "aliased_buffer.h"
#include "env-inl.h"
#include "fuzz_helper.h"
#include "libplatform/libplatform.h"
#include "node.h"
#include "node_internals.h"
#include "node_platform.h"
#include "util-inl.h"
#include "v8.h"
#include <cstdio>
#include <fuzzer/FuzzedDataProvider.h>
#include <stdlib.h>

using node::AliasedBufferBase;

/* General set up */
using ArrayBufferUniquePtr = std::unique_ptr<node::ArrayBufferAllocator, decltype(&node::FreeArrayBufferAllocator)>;
using TracingAgentUniquePtr = std::unique_ptr<node::tracing::Agent>;
using NodePlatformUniquePtr = std::unique_ptr<node::NodePlatform>;

static TracingAgentUniquePtr tracing_agent;
static NodePlatformUniquePtr platform;
static uv_loop_t current_loop;

const char *ciphers[132] = {"aes-128-cbc",
                            "aes-128-cbc-hmac-sha1",
                            "aes-128-cbc-hmac-sha256",
                            "aes-128-ccm",
                            "aes-128-cfb",
                            "aes-128-cfb1",
                            "aes-128-cfb8",
                            "aes-128-ctr",
                            "aes-128-ecb",
                            "aes-128-gcm",
                            "aes-128-ocb",
                            "aes-128-ofb",
                            "aes-128-xts",
                            "aes-192-cbc",
                            "aes-192-ccm",
                            "aes-192-cfb",
                            "aes-192-cfb1",
                            "aes-192-cfb8",
                            "aes-192-ctr",
                            "aes-192-ecb",
                            "aes-192-gcm",
                            "aes-192-ocb",
                            "aes-192-ofb",
                            "aes-256-cbc",
                            "aes-256-cbc-hmac-sha1",
                            "aes-256-cbc-hmac-sha256",
                            "aes-256-ccm",
                            "aes-256-cfb",
                            "aes-256-cfb1",
                            "aes-256-cfb8",
                            "aes-256-ctr",
                            "aes-256-ecb",
                            "aes-256-gcm",
                            "aes-256-ocb",
                            "aes-256-ofb",
                            "aes-256-xts",
                            "aes128",
                            "aes128-wrap",
                            "aes192",
                            "aes192-wrap",
                            "aes256",
                            "aes256-wrap",
                            "aria-128-cbc",
                            "aria-128-ccm",
                            "aria-128-cfb",
                            "aria-128-cfb1",
                            "aria-128-cfb8",
                            "aria-128-ctr",
                            "aria-128-ecb",
                            "aria-128-gcm",
                            "aria-128-ofb",
                            "aria-192-cbc",
                            "aria-192-ccm",
                            "aria-192-cfb",
                            "aria-192-cfb1",
                            "aria-192-cfb8",
                            "aria-192-ctr",
                            "aria-192-ecb",
                            "aria-192-gcm",
                            "aria-192-ofb",
                            "aria-256-cbc",
                            "aria-256-ccm",
                            "aria-256-cfb",
                            "aria-256-cfb1",
                            "aria-256-cfb8",
                            "aria-256-ctr",
                            "aria-256-ecb",
                            "aria-256-gcm",
                            "aria-256-ofb",
                            "aria128",
                            "aria192",
                            "aria256",
                            "camellia-128-cbc",
                            "camellia-128-cfb",
                            "camellia-128-cfb1",
                            "camellia-128-cfb8",
                            "camellia-128-ctr",
                            "camellia-128-ecb",
                            "camellia-128-ofb",
                            "camellia-192-cbc",
                            "camellia-192-cfb",
                            "camellia-192-cfb1",
                            "camellia-192-cfb8",
                            "camellia-192-ctr",
                            "camellia-192-ecb",
                            "camellia-192-ofb",
                            "camellia-256-cbc",
                            "camellia-256-cfb",
                            "camellia-256-cfb1",
                            "camellia-256-cfb8",
                            "camellia-256-ctr",
                            "camellia-256-ecb",
                            "camellia-256-ofb",
                            "camellia128",
                            "camellia192",
                            "camellia256",
                            "chacha20",
                            "chacha20-poly1305",
                            "des-ede",
                            "des-ede-cbc",
                            "des-ede-cfb",
                            "des-ede-ecb",
                            "des-ede-ofb",
                            "des-ede3",
                            "des-ede3-cbc",
                            "des-ede3-cfb",
                            "des-ede3-cfb1",
                            "des-ede3-cfb8",
                            "des-ede3-ecb",
                            "des-ede3-ofb",
                            "des3",
                            "des3-wrap",
                            "id-aes128-CCM",
                            "id-aes128-GCM",
                            "id-aes128-wrap",
                            "id-aes128-wrap-pad",
                            "id-aes192-CCM",
                            "id-aes192-GCM",
                            "id-aes192-wrap",
                            "id-aes192-wrap-pad",
                            "id-aes256-CCM",
                            "id-aes256-GCM",
                            "id-aes256-wrap",
                            "id-aes256-wrap-pad",
                            "id-smime-alg-CMS3DESwrap",
                            "sm4",
                            "sm4-cbc",
                            "sm4-cfb",
                            "sm4-ctr",
                            "sm4-ecb",
                            "sm4-ofb"};

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  uv_os_unsetenv("NODE_OPTIONS");
  std::vector<std::string> node_argv{"fuzz_env"};
  std::vector<std::string> exec_argv;
  std::vector<std::string> errors;

  node::InitializeNodeWithArgs(&node_argv, &exec_argv, &errors);

  tracing_agent = std::make_unique<node::tracing::Agent>();
  node::tracing::TraceEventHelper::SetAgent(tracing_agent.get());
  node::tracing::TracingController *tracing_controller = tracing_agent->GetTracingController();
  CHECK_EQ(0, uv_loop_init(&current_loop));
  static constexpr int kV8ThreadPoolSize = 4;
  platform.reset(new node::NodePlatform(kV8ThreadPoolSize, tracing_controller));
  v8::V8::InitializePlatform(platform.get());
  cppgc::InitializeProcess(platform->GetPageAllocator());
  v8::V8::Initialize();
  return 0;
}

void EnvTest(v8::Isolate *isolate_, char *env_string) {
  printf("%s\n", env_string);
  const v8::HandleScope handle_scope(isolate_);
  Argv argv;

  node::EnvironmentFlags::Flags flags = node::EnvironmentFlags::kDefaultFlags;
  auto isolate = handle_scope.GetIsolate();
  v8::Local<v8::Context> context_ = node::NewContext(isolate);
  context_->Enter();

  node::IsolateData *isolate_data_ = node::CreateIsolateData(isolate, &current_loop, platform.get());
  std::vector<std::string> args(*argv, *argv + 1);
  std::vector<std::string> exec_args(*argv, *argv + 1);
  node::Environment *environment_ = node::CreateEnvironment(isolate_data_, context_, args, exec_args, flags);
  node::Environment *envi = environment_;
  SetProcessExitHandler(envi, [&](node::Environment *env_, int exit_code) { node::Stop(envi); });
  node::LoadEnvironment(envi, env_string);

  // Cleanup!
  node::FreeEnvironment(environment_);
  node::FreeIsolateData(isolate_data_);
  context_->Exit();
}

std::string s1 = "const crypto  = require('crypto');\n"
                 "const enc_key = \"";
// enc_key
std::string s2 = "\";\n"
                 "const vector = \"";
// vector
std::string s3 = "\";\n"
                 "const textToEncrypt = \"";
// textToEncrypt
std::string s4 = "\";\n"
                 "const cipherAlg = \"";
// CHOSEN_CIPHER
std::string s5 = "\";\n"
                 "function encrypt(text){\n"
                 "  const cipher = crypto.createCipheriv(cipherAlg, Buffer.from(enc_key), Buffer.from(vector))\n"
                 "  var encrypted = cipher.update(text, 'utf8', 'hex');\n"
                 "  encrypted += cipher.final('hex');\n"
                 "  return encrypted\n"
                 "}\n"
                 "function decrypt(text){\n"
                 "  const decipher = crypto.createDecipheriv(cipherAlg, Buffer.from(enc_key), Buffer.from(vector));\n"
                 "  let decrypted = decipher.update(text, 'hex', 'utf8');\n"
                 "  decrypted += decipher.final('utf8');\n"
                 "  return decrypted\n"
                 "}\n"
                 "const crypted = encrypt(textToEncrypt);\n"
                 "var _ = decrypt(crypted);\n";

class FuzzerFixtureHelper {
public:
  v8::Isolate *isolate_;
  ArrayBufferUniquePtr allocator;

  FuzzerFixtureHelper() : allocator(ArrayBufferUniquePtr(node::CreateArrayBufferAllocator(), &node::FreeArrayBufferAllocator)) {
    isolate_ = NewIsolate(allocator.get(), &current_loop, platform.get());
    CHECK_NOT_NULL(isolate_);
    isolate_->Enter();
  };

  void Teardown() {
    platform->DrainTasks(isolate_);
    isolate_->Exit();
    platform->UnregisterIsolate(isolate_);
    isolate_->Dispose();
    isolate_ = nullptr;
  }
};

// checks for unescaped double quotes which would break the script
bool hasUnescapedQuotes(std::string s) {
  for (int i = 0; i < s.length(); i++) {
    if (s[i] == '"') {
      // Found a double quote. Check if it is escaped
      if (i == 0) {
        return true;
      }
      if (s.at(i - 1) != '\\') {
        return true;
      }
    }
  }
  return false;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data2, size_t size) {
  FuzzedDataProvider prov(data2, size);
  std::string enc_key = prov.ConsumeRandomLengthString();
  if (enc_key.length() != 32) {
    return 0;
  }
  std::string vector = prov.ConsumeRandomLengthString();
  if (vector.length() != 16) {
    return 0;
  }
  std::string textToEncrypt = prov.ConsumeRandomLengthString();

  int max = sizeof(ciphers) / sizeof(ciphers[0]);
  int min = 0;
  int cipher_array_index = prov.ConsumeIntegralInRange<int>(min, max);

  if (hasUnescapedQuotes(enc_key)) {
    return 0;
  }
  if (hasUnescapedQuotes(vector)) {
    return 0;
  }
  if (hasUnescapedQuotes(textToEncrypt)) {
    return 0;
  }

  const char *chosen_cipher = ciphers[cipher_array_index];

  std::stringstream stream;
  stream << s1 << enc_key << s2 << vector << s3 << textToEncrypt << s4 << chosen_cipher << s5 << std::endl;
  std::string js_code = stream.str();
  FuzzerFixtureHelper ffh;
  EnvTest(ffh.isolate_, (char *)js_code.c_str());
  ffh.Teardown();
  return 0;
}
