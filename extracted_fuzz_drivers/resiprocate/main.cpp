extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);
extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

int main(int argc, char *argv[]) {
  const unsigned long size = 42;
  const unsigned char data[size] = {};

  // LLVMFuzzerInitialize(&argc, &argv);
  LLVMFuzzerTestOneInput(data, size);
  return 0;
}