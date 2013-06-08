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
static Persistent<String> onclearInError_sym;
static Persistent<String> onencOutError_sym;


TLSWrap::TLSWrap(Handle<Object> object, Handle<Object> sc) : TCPWrap(object),
                                                             ssl_(NULL),
                                                             enc_in_(NULL),
                                                             enc_out_(NULL),
                                                             clear_in_(NULL),
                                                             write_size_(0) {
  sc_ = ObjectWrap::Unwrap<SecureContext>(sc);
  sc_handle_ = Persistent<Object>::New(node_isolate, sc);

  // TODO(indutny) support it
  SSL_CTX_sess_set_get_cb(sc_->ctx_, NULL);
  SSL_CTX_sess_set_new_cb(sc_->ctx_, NULL);

  QUEUE_INIT(&write_item_queue_);
}


TLSWrap::~TLSWrap() {
  SSL_free(ssl_);
  ssl_ = NULL;
  enc_in_ = NULL;
  enc_out_ = NULL;
  delete clear_in_;
  clear_in_ = NULL;
}


TLSWrap::WriteItem::~WriteItem() {
  w_ = NULL;
  cb_ = NULL;
}


void TLSWrap::InvokeQueued(int status) {
  QUEUE* q = NULL;
  QUEUE_FOREACH(q, &write_item_queue_) {
    WriteItem* wi = container_of(q, WriteItem, member_);
    wi->cb_(&wi->w_->req_, status);
    delete wi;
  }

  // Empty queue
  QUEUE_INIT(&write_item_queue_);
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
  // Write in progress
  if (write_size_ != 0)
    return;

  // No data to write
  if (BIO_pending(enc_out_) == 0) {
    InvokeQueued(0);
    return;
  }

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
    wrap->InvokeQueued(status);
    return;
  }

  // Commit
  NodeBIO::FromBIO(wrap->enc_out_)->Read(NULL, wrap->write_size_);

  // Try writing more data
  wrap->write_size_ = 0;
  wrap->EncOut();
}


Handle<Value> TLSWrap::GetSSLError(int status, int* err) {
  HandleScope scope(node_isolate);

  *err = SSL_get_error(ssl_, status);
  switch (*err) {
   case SSL_ERROR_NONE:
   case SSL_ERROR_WANT_READ:
   case SSL_ERROR_WANT_WRITE:
    break;
   case SSL_ERROR_ZERO_RETURN:
    return String::NewSymbol("ZERO_RETURN");
    break;
   default:
    {
      BUF_MEM* mem;
      BIO* bio;

      assert(*err == SSL_ERROR_SSL || *err == SSL_ERROR_SYSCALL);

      bio = BIO_new(BIO_s_mem());
      assert(bio != NULL);
      ERR_print_errors(bio);
      BIO_get_mem_ptr(bio, &mem);
      Handle<Value> r = Exception::Error(String::New(mem->data, mem->length));
      BIO_free_all(bio);

      return r;
    }
  }
  return Handle<Value>();
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
    int err;
    Handle<Value> argv = GetSSLError(read, &err);

    if (!argv.IsEmpty())
      MakeCallback(object_, onclearOutError_sym, 1, &argv);
  }
}


bool TLSWrap::ClearIn() {
  int written;
  while (clear_in_->Length() > 0) {
    size_t avail = 0;
    char* data = clear_in_->Peek(&avail);
    written = SSL_write(ssl_, data, avail);
    assert(written == -1 || written == static_cast<int>(avail));
    if (written == -1)
      break;
    clear_in_->Read(NULL, avail);
  }

  // All written
  if (clear_in_->Length() == 0) {
    assert(written >= 0);
    return true;
  }

  // Error or partial write
  int err;
  Handle<Value> argv = GetSSLError(written, &err);
  if (!argv.IsEmpty())
    MakeCallback(object_, onclearInError_sym, 1, &argv);

  return false;
}


int TLSWrap::DoWrite(WriteWrap* w,
                     uv_buf_t* bufs,
                     int count,
                     uv_stream_t* send_handle,
                     uv_write_cb cb) {
  assert(send_handle == NULL);

  // Queue callback to execute it on next tick
  WriteItem* wi = new WriteItem(w, cb);

  // Assign handle, because AfterWrite expects it
  // XXX: handle this in stream_wrap.cc
  w->req_.handle = reinterpret_cast<uv_stream_t*>(&handle_);
  QUEUE_INSERT_TAIL(&write_item_queue_, &wi->member_);

  // Process enqueued data first
  if (!ClearIn()) {
    // If there're still data to process - enqueue current one
    for (int i = 0; i < count; i++)
      clear_in_->Write(bufs[i].base, bufs[i].len);
    return 0;
  }

  int i;
  int written;
  for (i = 0; i < count; i++) {
    written = SSL_write(ssl_, bufs[i].base, bufs[i].len);
    assert(written == -1 || written == static_cast<int>(bufs[i].len));
    if (written == -1)
      break;
  }

  if (i != count) {
    int err;
    Handle<Value> argv = GetSSLError(written, &err);
    if (!argv.IsEmpty()) {
      MakeCallback(object_, onclearInError_sym, 1, &argv);
      return -1;
    }

    // No errors, queue rest
    for (; i < count; i++)
      clear_in_->Write(bufs[i].base, bufs[i].len);
  }

  return 0;
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
  ClearIn();
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
  onclearInError_sym = NODE_PSYMBOL("onclearInError");
  onclearOutError_sym = NODE_PSYMBOL("onclearOutError");
}


} // namespace node

NODE_MODULE(node_tls_wrap, node::TLSWrap::Initialize)
