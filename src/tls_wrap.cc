#include "tls_wrap.h"
#include "node_buffer.h" // Buffer
#include "node_crypto.h" // SecureContext
#include "node_crypto_bio.h" // NodeBIO

namespace node {

using namespace v8;
using crypto::SecureContext;

static Persistent<Function> tlsConstructor;
static Persistent<String> onread_sym;
static Persistent<String> onclearOutError_sym;
static Persistent<String> onencOutError_sym;


TLSWrap::TLSWrap(Handle<Object> object, Handle<Object> sc) : TCPWrap(object),
                                                             ssl_(NULL),
                                                             enc_in_(NULL),
                                                             enc_out_(NULL),
                                                             clear_in_(NULL),
                                                             write_size_(0) {
  sc_ = ObjectWrap::Unwrap<SecureContext>(sc);
  sc_handle_ = Persistent<Object>::New(node_isolate, sc);
}


TLSWrap::~TLSWrap() {
}


void TLSWrap::InitClient() {
  // Initialize SSL
  ssl_ = SSL_new(sc_->ctx_);
  enc_in_ = BIO_new(NodeBIO::GetMethod());
  enc_out_ = BIO_new(NodeBIO::GetMethod());

  SSL_set_accept_state(ssl_);
  SSL_set_bio(ssl_, enc_in_, enc_out_);

  // Initialize ring for queud clear data
  clear_in_ = new NodeBIO();
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


void TLSWrap::EncOut() {
  if (write_size_ != 0 || BIO_pending(enc_out_) == 0)
    return;

  uv_stream_t* stream = reinterpret_cast<uv_stream_t*>(&handle_);

  char* data = NodeBIO::FromBIO(enc_out_)->Peek(&write_size_);
  assert(write_size_ != 0);

  uv_write_t req;
  req.data = this;
  uv_buf_t buf = uv_buf_init(data, write_size_);
  uv_write(&req, stream, &buf, 1, EncOutCb);
}


void TLSWrap::EncOutCb(uv_write_t* req, int status) {
  TLSWrap* wrap = reinterpret_cast<TLSWrap*>(req->data);

  // Handle error
  if (status) {
    SetErrno(uv_last_error(uv_default_loop()));
    Handle<Value> arg = Integer::New(status, node_isolate);
    MakeCallback(wrap->object_, onencOutError_sym, 1, &arg);
    return;
  }

  // Commit
  NodeBIO::FromBIO(wrap->enc_out_)->Read(NULL, wrap->write_size_);

  // Try writing more data
  wrap->write_size_ = 0;
  wrap->EncOut();
}


void TLSWrap::ClearOut() {
  HandleScope scope(node_isolate);

  assert(ssl_ != NULL);

  char out[kClearOutChunkSize];
  int read;
  do {
    read = SSL_read(ssl_, out, sizeof(out));
    if (read > 0) {
      Handle<Value> argv[3] = {
        Buffer::New(out, read)->handle_,
        Integer::New(0, node_isolate),
        Integer::New(read, node_isolate)
      };
      MakeCallback(object_, onread_sym, ARRAY_SIZE(argv), argv);
    }
  } while (read > 0);

  if (read == -1) {
    int err = SSL_get_error(ssl_, read);
    Handle<Value> argv;

    switch (err) {
     case SSL_ERROR_NONE:
     case SSL_ERROR_WANT_READ:
     case SSL_ERROR_WANT_WRITE:
      break;
     case SSL_ERROR_ZERO_RETURN:
      argv = String::NewSymbol("ZERO_RETURN");
      break;
     default:
      {
        BUF_MEM* mem;
        BIO *bio;

        assert(err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL);

        if ((bio = BIO_new(BIO_s_mem()))) {
          ERR_print_errors(bio);
          BIO_get_mem_ptr(bio, &mem);
          argv = Exception::Error(String::New(mem->data, mem->length));
          BIO_free_all(bio);
        }
      }
    }

    if (!argv.IsEmpty())
      MakeCallback(object_, onclearOutError_sym, 1, &argv);
  }
}


uv_buf_t TLSWrap::DoAlloc(uv_handle_t* handle, size_t suggested_size) {
  size_t size = suggested_size;
  char* data = NodeBIO::FromBIO(enc_in_)->Reserve(&size);
  return uv_buf_init(data, size);
}


void TLSWrap::HandleRead(uv_stream_t* handle,
                         ssize_t nread,
                         uv_buf_t buf,
                         uv_handle_type pending) {
  // Only client connections can receive data
  assert(ssl_ != NULL);

  // Commit read data
  NodeBIO::FromBIO(enc_in_)->Commit(nread);

  // Cycle OpenSSL state
  ClearOut();
  EncOut();
}


void TLSWrap::HandleFailedRead(uv_buf_t buf) {
  // Ignore!
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
  if (uv_accept(server, client_handle))
    return Handle<Object>();

  // Initialize ssl connection
  client_wrap->InitClient();

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

  onread_sym = NODE_PSYMBOL("onread");
  onencOutError_sym = NODE_PSYMBOL("onencOutError");
  onclearOutError_sym = NODE_PSYMBOL("onclearOutError");
}


} // namespace node

NODE_MODULE(node_tls_wrap, node::TLSWrap::Initialize)
