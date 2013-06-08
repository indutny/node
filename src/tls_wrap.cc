#include "tls_wrap.h"
#include "node_crypto.h" // SecureContext

namespace node {

using namespace v8;
using crypto::SecureContext;

static Persistent<Function> tlsConstructor;


TLSWrap::TLSWrap(Handle<Object> object, Handle<Object> sc) : TCPWrap(object) {
  sc_ = ObjectWrap::Unwrap<SecureContext>(sc);
  sc_handle_ = Persistent<Object>::New(node_isolate, sc);
}


TLSWrap::~TLSWrap() {
}


Local<Object> TLSWrap::Instantiate(Handle<Value> sc) {
  // If this assert fire then process.binding('tls_wrap') hasn't been
  // called yet.
  assert(tlsConstructor.IsEmpty() == false);

  HandleScope scope(node_isolate);
  Local<Object> obj = tlsConstructor->NewInstance(1, &sc);

  return scope.Close(obj);
}


TLSWrap* TLSWrap::Unwrap(v8::Local<v8::Object> obj) {
  assert(!obj.IsEmpty());
  assert(obj->InternalFieldCount() > 0);
  return static_cast<TLSWrap*>(obj->GetAlignedPointerFromInternalField(0));
}


Handle<Value> TLSWrap::New(const Arguments& args) {
  // This constructor should not be exposed to public javascript.
  // Therefore we assert that we are not trying to call this as a
  // normal function.
  assert(args.IsConstructCall());

  HandleScope scope(node_isolate);

  if (args.Length() < 1)
    return ThrowException(Exception::TypeError(String::New(
            "First argument should be a SecureContext instance")));

  TLSWrap* wrap = new TLSWrap(args.This(), args[0].As<Object>());
  assert(wrap);

  return scope.Close(args.This());
}


int TLSWrap::ReadStart(uv_stream_t* stream, bool ipc_pipe) {
  return 0;
}


Handle<Object> TLSWrap::Accept(uv_stream_t* server) {
  HandleScope scope(node_isolate);

  // Instantiate the client javascript object and handle.
  Local<Object> client_obj = Instantiate(sc_handle_);

  // Unwrap the client javascript object.
  assert(client_obj->InternalFieldCount() > 0);

  void* client_wrap_v = client_obj->GetAlignedPointerFromInternalField(0);
  TLSWrap* client_wrap = static_cast<TLSWrap*>(client_wrap_v);
  uv_stream_t* client_handle =
      reinterpret_cast<uv_stream_t*>(&client_wrap->handle_);
  if (uv_accept(server, client_handle)) return Handle<Object>();

  return scope.Close(client_obj);
}


void TLSWrap::Initialize(v8::Handle<v8::Object> target) {
  HandleWrap::Initialize(target);

  HandleScope scope(node_isolate);

  Local<FunctionTemplate> t = FunctionTemplate::New(New);
  t->SetClassName(String::NewSymbol("TLS"));
  t->InstanceTemplate()->SetInternalFieldCount(1);
  InitTemplate(t);

  tlsConstructor = Persistent<Function>::New(node_isolate, t->GetFunction());

  target->Set(String::NewSymbol("TLS"), tlsConstructor);
}


} // namespace node

NODE_MODULE(node_tls_wrap, node::TLSWrap::Initialize)
