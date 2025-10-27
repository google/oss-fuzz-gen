/*
   Copyright The libcups Developers.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "file.h"
#include "ipp-private.h"
#include "string-private.h"
#include "test-internal.h"
#include <spawn.h>
#include <sys/wait.h>

typedef struct _ippdata_t {
  size_t rpos,          // Read position
      wused,            // Bytes used
      wsize;            // Max size of buffer
  ipp_uchar_t *wbuffer; // Buffer
} _ippdata_t;

ssize_t write_cb(_ippdata_t *data, ipp_uchar_t *buffer, size_t bytes);

// 'write_cb()' - Write data into a buffer.
ssize_t                       // O - Number of bytes written
write_cb(_ippdata_t *data,    // I - Data
         ipp_uchar_t *buffer, // I - Buffer to write
         size_t bytes)        // I - Number of bytes to write
{
  size_t count; // Number of bytes

  // Loop until all bytes are written...
  if ((count = data->wsize - data->wused) > bytes)
    count = bytes;

  memcpy(data->wbuffer + data->wused, buffer, count);
  data->wused += count;

  // Return the number of bytes written...
  return ((ssize_t)count);
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  if (Size == 0 || Size > 262144) {
    return 0; // Handle empty input gracefully
  } // Handle large input gracefully (limiting to 262144 bytes for now

  int status = 0;
  cups_file_t *fp;
  ipp_state_t state;
  ipp_t *request;
  ipp_uchar_t buffer[262144];

  request = ippNewRequest(IPP_OP_PRINT_JOB); // Create a new IPP request (operation type is IPP_OP_PRINT_JOB
  _ippdata_t ippdata;
  ippdata.wused = 0;
  ippdata.wsize = sizeof(buffer);
  ippdata.wbuffer = buffer;

  // create new ipp

  while ((state = ippWriteIO(&ippdata, (ipp_io_cb_t)write_cb, 1, NULL, request)) != IPP_STATE_DATA) {
    if (state == IPP_STATE_ERROR)
      break;
  }
  if (state != IPP_STATE_DATA) {
    status = 1;
  }

  ippDelete(request);

  // testing writing
  memcpy((char *)ippdata.wbuffer, (char *)Data, Size);
  ippdata.wused = Size;

  const char *filename = "/tmp/tmp.ipp";

  if ((fp = cupsFileOpen(filename, "w")) == NULL) {
    return 1;
  }

  cupsFileWrite(fp, (char *)buffer, ippdata.wused);
  cupsFileClose(fp);

  // Testing Reading
  if ((fp = cupsFileOpen(filename, "r")) == NULL) {
    return 1;
  }

  request = ippNew();

  do {
    state = ippReadIO(fp, (ipp_io_cb_t)cupsFileRead, 1, NULL, request);
  } while (state == IPP_STATE_ATTRIBUTE);

  cupsFileClose(fp);

  fp = cupsFileOpen("/dev/null", "w");

  ippSetState(request, IPP_STATE_IDLE);

  do {
    state = ippWriteIO(fp, (ipp_io_cb_t)cupsFileWrite, 1, NULL, request);
  } while (state == IPP_STATE_ATTRIBUTE);

  cupsFileClose(fp);
  ippDelete(request);

  // clean up file
  unlink(filename);
  return status;
}