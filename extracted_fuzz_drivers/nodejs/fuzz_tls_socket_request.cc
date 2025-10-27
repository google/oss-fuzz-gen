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

std::string script_header = "const tls = require('tls');\n"
                            "const https = require('https');\n"
                            "const { setEnvironmentData } = require('worker_threads');\n"
                            "const { send } = require('process');\n"
                            "const key = `-----BEGIN EC PARAMETERS-----\n"
                            "BggqhkjOPQMBBw==\n"
                            "-----END EC PARAMETERS-----\n"
                            "-----BEGIN EC PRIVATE KEY-----\n"
                            "MHcCAQEEIDKfHHbiJMdu2STyHL11fWC7psMY19/gUNpsUpkwgGACoAoGCCqGSM49\n"
                            "AwEHoUQDQgAEItqm+pYj3Ca8bi5mBs+H8xSMxuW2JNn4I+kw3aREsetLk8pn3o81\n"
                            "PWBiTdSZrGBGQSy+UAlQvYeE6Z/QXQk8aw==\n"
                            "-----END EC PRIVATE KEY-----`\n"
                            "\n"
                            "const cert = `-----BEGIN CERTIFICATE-----\n"
                            "MIIBhjCCASsCFDJU1tCo88NYU//pE+DQKO9hUDsFMAoGCCqGSM49BAMCMEUxCzAJ\n"
                            "BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\n"
                            "dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjAwOTIyMDg1NDU5WhcNNDgwMjA3MDg1NDU5\n"
                            "WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY\n"
                            "SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"
                            "QgAEItqm+pYj3Ca8bi5mBs+H8xSMxuW2JNn4I+kw3aREsetLk8pn3o81PWBiTdSZ\n"
                            "rGBGQSy+UAlQvYeE6Z/QXQk8azAKBggqhkjOPQQDAgNJADBGAiEA7Bdn4F87KqIe\n"
                            "Y/ABy/XIXXpFUb2nyv3zV7POQi2lPcECIQC3UWLmfiedpiIKsf9YRIyO0uEood7+\n"
                            "glj2R1NNr1X68w==\n"
                            "-----END CERTIFICATE-----`\n"
                            "\n"
                            "const options = {\n"
                            "  key: key,\n"
                            "  cert: cert,\n"
                            "};\n"
                            "\n"
                            "var srv;\n"
                            "var socket;\n"
                            "var receivedResponse = 0;\n"
                            "\n"
                            "async function send_requests() {\n"
                            "  socket = tls.connect(4444, 'localhost', { rejectUnauthorized: false }, () => {\n"
                            "    const httpRequest = `GET / HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: Keep-alive\\r\\n\\r\\n`;\n";
std::string send_get_request = "    socket.write(httpRequest);\n";

std::string pr_decl1 = "    var postRequest = `POST / HTTP/1.1\\r\\nHost: localhost\\r\\nContent-Type: application/json\\r\\nContent-Length: ${Buffer.from('";
std::string pr_decl2 = "').length}\\r\\n\\r\\n\n";
std::string pr_decl3 = "`;\n";
std::string send_post_request = "    socket.write(postRequest);\n";
std::string script_footer = "  })\n"
                            "  socket.on('data', (data) => {\n"
                            "    receivedResponse++;\n"
                            "    if (receivedResponse === 6) {\n"
                            "      socket.end();\n"
                            "    }\n"
                            "  });\n"
                            "\n"
                            "  socket.on('end', () => {\n"
                            "    srv.close(() => {\n"
                            "    })\n"
                            "  });\n"
                            "}\n"
                            "function run_server() {\n"
                            "  srv = https.createServer(options, function (req, res) {\n"
                            "    res.writeHead(200, { 'Content-Type': 'text/plain' });\n"
                            "    res.end(\"end\");\n"
                            "  });\n"
                            "  srv.listen(4444, () => {\n"
                            "\n"
                            "  });\n"
                            "}\n"
                            "\n"
                            "run_server();\n"
                            "send_requests();\n";

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

// checks for unescaped backtics and double quotes which would break the script
bool isInvalid(std::string s) {
  char backtick = '`';
  for (int i = 0; i < s.length(); i++) {
    if (s[i] == backtick) {
      // Found a backtick. Check if it is escaped
      if (i == 0) {
        return true;
      }
      if (s.at(i - 1) != '\\') {
        return true;
      }
    }
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
  std::string post_request1_body = prov.ConsumeRandomLengthString();
  std::string post_request2_body = prov.ConsumeRandomLengthString();
  std::string post_request3_body = prov.ConsumeRandomLengthString();

  if (isInvalid(post_request1_body)) {
    return 0;
  }
  if (isInvalid(post_request2_body)) {
    return 0;
  }
  if (isInvalid(post_request3_body)) {
    return 0;
  }

  std::stringstream post_request1;
  post_request1 << pr_decl1 << post_request1_body << pr_decl2 << post_request1_body << pr_decl3 << send_post_request << send_get_request << std::endl;
  std::string pr1_str = post_request1.str();

  std::stringstream post_request2;
  post_request2 << pr_decl1 << post_request2_body << pr_decl2 << post_request2_body << pr_decl3 << send_post_request << send_get_request << std::endl;
  std::string pr2_str = post_request2.str();

  std::stringstream post_request3;
  post_request3 << pr_decl1 << post_request3_body << pr_decl2 << post_request3_body << pr_decl3 << send_post_request << send_get_request << std::endl;
  std::string pr3_str = post_request3.str();

  std::stringstream stream;
  stream << script_header << pr1_str << pr2_str << pr3_str << script_footer << std::endl;
  std::string js_code = stream.str();
  FuzzerFixtureHelper ffh;
  EnvTest(ffh.isolate_, (char *)js_code.c_str());
  ffh.Teardown();
  return 0;
}
