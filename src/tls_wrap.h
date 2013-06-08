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

#include "v8.h"
#include "tcp_wrap.h"

namespace node {

// Forward-declarations
namespace crypto {
  class SecureContext;
}

class TLSWrap : public TCPWrap {
 public:
  static v8::Local<v8::Object> Instantiate(v8::Handle<v8::Value> sc);
  static TLSWrap* Unwrap(v8::Local<v8::Object> obj);
  static void Initialize(v8::Handle<v8::Object> target);

 protected:
  TLSWrap(v8::Handle<v8::Object> object, v8::Handle<v8::Object> sc);
  ~TLSWrap();

  int ReadStart(uv_stream_t* stream, bool ipc_pipe);
  v8::Handle<v8::Object> Accept(uv_stream_t* server);
  static v8::Handle<v8::Value> New(const v8::Arguments& args);

  crypto::SecureContext* sc_;
  v8::Persistent<v8::Object> sc_handle_;
};

} // namespace node

#endif // TLP_WRAP_H_
