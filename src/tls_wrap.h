// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

#ifndef TLP_WRAP_H_
#define TLP_WRAP_H_

#include <openssl/ssl.h>

#include "v8.h"
#include "tcp_wrap.h"
#include "queue.h"

namespace node {

// Forward-declarations
class NodeBIO;
class WriteWrap;
namespace crypto {
  class SecureContext;
}

class TLSWrap : public TCPWrap {
 public:
  static v8::Local<v8::Object> Instantiate(v8::Handle<v8::Value> sc);
  static TLSWrap* Unwrap(v8::Local<v8::Object> obj);
  static void Initialize(v8::Handle<v8::Object> target);

 protected:
  static const int kClearOutChunkSize = 1024;
  class WriteItem {
   public:
    WriteItem(WriteWrap* w, uv_write_cb cb) : w_(w), cb_(cb) {
    }
    ~WriteItem();

    WriteWrap* w_;
    uv_write_cb cb_;
    QUEUE member_;
  };

  TLSWrap(v8::Handle<v8::Object> object, v8::Handle<v8::Object> sc);
  ~TLSWrap();

  void InitClient();
  void EncOut();
  static void EncOutCb(uv_write_t* req, int status);
  bool ClearIn();
  void ClearOut();
  void InvokeQueued(int status);

  v8::Handle<v8::Value> GetSSLError(int status, int* err);

  int DoWrite(WriteWrap* w,
              uv_buf_t* bufs,
              int count,
              uv_stream_t* send_handle,
              uv_write_cb cb);
  uv_buf_t DoAlloc(uv_handle_t* handle, size_t suggested_size);
  void HandleRead(uv_stream_t* handle,
                  ssize_t nread,
                  uv_buf_t buf,
                  uv_handle_type pending);
  void HandleFailedRead(uv_buf_t buf);

  v8::Handle<v8::Object> Accept(uv_stream_t* server);
  static v8::Handle<v8::Value> New(const v8::Arguments& args);

  crypto::SecureContext* sc_;
  v8::Persistent<v8::Object> sc_handle_;

  SSL* ssl_;
  BIO* enc_in_;
  BIO* enc_out_;
  NodeBIO* clear_in_;
  uv_write_t write_req_;
  size_t write_size_;
  QUEUE write_item_queue_;
};

} // namespace node

#endif // TLP_WRAP_H_
