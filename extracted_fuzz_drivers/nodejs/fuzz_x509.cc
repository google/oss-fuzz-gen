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

std::string S1 = "const { X509Certificate } = require('node:crypto');\n"
                 "const x509 = new X509Certificate(\"";
// RANDOM
std::string S2 = "\");\n"
                 "var _ = x509.subject;\n"
                 "var _ = x509.ca;\n"
                 "x509.checkEmail(\"";
// RANDOM
std::string S3 = "\");\n"
                 "x509.checkHost(\"";
// RANDOM
std::string S4 = "\");\n"
                 "x509.checkIP(\"";
// RANDOM
std::string S5 = "\");\n"
                 "var _ = x509.fingerprint;\n"
                 "var _ = x509.fingerprint512;\n"
                 "var _ = x509.infoAccess;\n"
                 "var _ = x509.issuer;\n"
                 "var _ = x509.issuerCertificate;\n"
                 "var _ = x509.extKeyUsage;\n"
                 "var _ = x509.raw;\n"
                 "var _ = x509.serialNumber;\n"
                 "var _ = x509.subject;\n"
                 "var _ = x509.subjectAltName;\n"
                 "var _ = x509.toJSON();\n"
                 "var _ = x509.toLegacyObject();\n"
                 "var _ = x509.toString();\n"
                 "var _ = x509.validFrom;\n"
                 "var _ = x509.validTo;\n"
                 "var _ = x509.verify(x509.publicKey);\n";

void EnvTest(v8::Isolate *isolate_, char *env_string) {
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data2, size_t size) {
  FuzzedDataProvider prov(data2, size);
  std::string r1 = prov.ConsumeRandomLengthString();
  std::string r2 = prov.ConsumeRandomLengthString();
  std::string r3 = prov.ConsumeRandomLengthString();
  std::string r4 = prov.ConsumeRandomLengthString();
  if (hasUnescapedDoubleQuotes(r1)) {
    return 0;
  }
  if (hasUnescapedDoubleQuotes(r2)) {
    return 0;
  }
  if (hasUnescapedDoubleQuotes(r3)) {
    return 0;
  }
  if (hasUnescapedDoubleQuotes(r4)) {
    return 0;
  }
  std::stringstream stream;
  stream << S1 << r1 << S2 << r2 << S3 << r3 << S4 << r4 << S5 << std::endl;
  std::string js_code = stream.str();
  FuzzerFixtureHelper ffh;
  EnvTest(ffh.isolate_, (char *)js_code.c_str());
  ffh.Teardown();
  return 0;
}
