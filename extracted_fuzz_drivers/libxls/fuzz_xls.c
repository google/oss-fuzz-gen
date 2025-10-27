
#include "xls.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  xlsWorkBook *work_book = xls_open_buffer(Data, Size, NULL, NULL);
  if (work_book) {
    for (int i = 0; i < work_book->sheets.count; i++) {
      xlsWorkSheet *work_sheet = xls_getWorkSheet(work_book, i);
      xls_parseWorkSheet(work_sheet);
      xls_close_WS(work_sheet);
    }
    xls_close_WB(work_book);
  }
  return 0;
}
