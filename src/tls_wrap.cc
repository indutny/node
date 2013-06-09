#include "tls_wrap.h"
#include "node_buffer.h" // Buffer
#include "node_crypto.h" // SecureContext
#include "node_crypto_bio.h" // NodeBIO
#include "node_wrap.h" // WITH_GENERIC_STREAM

namespace node {

using namespace v8;
using crypto::SecureContext;

static Persistent<String> onread_sym;
static Persistent<String> onerror_sym;


TLSCallbacks::TLSCallbacks(Kind kind,
                           Handle<Object> sc,
                           StreamWrapCallbacks* old)
    : StreamWrapCallbacks(old),
      kind_(kind),
      old_(old),
      ssl_(NULL),
      enc_in_(NULL),
      enc_out_(NULL),
      clear_in_(NULL),
      write_size_(0) {

  // Persist SecureContext
  sc_ = ObjectWrap::Unwrap<SecureContext>(sc);
  sc_handle_ = Persistent<Object>::New(node_isolate, sc);

  // TODO(indutny) support it
  SSL_CTX_sess_set_get_cb(sc_->ctx_, NULL);
  SSL_CTX_sess_set_new_cb(sc_->ctx_, NULL);

  // Initialize queue for clearIn writes
  QUEUE_INIT(&write_item_queue_);
}


TLSCallbacks::~TLSCallbacks() {
  delete old_;

  SSL_free(ssl_);
  ssl_ = NULL;
  enc_in_ = NULL;
  enc_out_ = NULL;
  delete clear_in_;
  clear_in_ = NULL;

  sc_ = NULL;
  sc_handle_.Dispose();
  sc_handle_.Clear();
}


void TLSCallbacks::InvokeQueued(int status) {
  QUEUE* q = reinterpret_cast<QUEUE*>(QUEUE_NEXT(&write_item_queue_));

  while (q != &write_item_queue_) {
    WriteItem* wi = container_of(q, WriteItem, member_);
    wi->cb_(&wi->w_->req_, status);
    delete wi;
    q = reinterpret_cast<QUEUE*>(QUEUE_NEXT(q));
  }

  // Empty queue
  QUEUE_INIT(&write_item_queue_);
}


void TLSCallbacks::InitSSL() {
  if (ssl_ != NULL)
    return;

  // Initialize SSL
  ssl_ = SSL_new(sc_->ctx_);
  enc_in_ = BIO_new(NodeBIO::GetMethod());
  enc_out_ = BIO_new(NodeBIO::GetMethod());

  SSL_set_bio(ssl_, enc_in_, enc_out_);
  if (kind_ == kTLSServer)
    SSL_set_accept_state(ssl_);
  else if (kind_ == kTLSClient)
    SSL_set_connect_state(ssl_);

  // Initialize ring for queud clear data
  clear_in_ = new NodeBIO();
}


Handle<Value> TLSCallbacks::Wrap(const Arguments& args) {
  HandleScope scope(node_isolate);

  if (args.Length() < 1 || !args[0]->IsObject())
    return ThrowTypeError("First argument should be a SecureContext instance");
  if (args.Length() < 2 || !args[1]->IsObject())
    return ThrowTypeError("Second argument should be a StreamWrap instance");
  if (args.Length() < 3 || !args[2]->IsBoolean())
    return ThrowTypeError("Third argument should be boolean");

  Local<Object> sc = args[0].As<Object>();
  Local<Object> stream = args[1].As<Object>();
  Kind kind = args[2]->IsTrue() ? kTLSServer : kTLSClient;

  WITH_GENERIC_STREAM(stream, {
    wrap->callbacks_ = new TLSCallbacks(kind, sc, wrap->callbacks_);
  });

  return Null();
}


void TLSCallbacks::EncOut() {
  // Write in progress
  if (write_size_ != 0)
    return;

  // No data to write
  if (BIO_pending(enc_out_) == 0) {
    InvokeQueued(0);
    return;
  }

  char* data = NodeBIO::FromBIO(enc_out_)->Peek(&write_size_);
  assert(write_size_ != 0);

  write_req_.data = this;
  uv_buf_t buf = uv_buf_init(data, write_size_);
  uv_write(&write_req_, wrap_->GetStream(), &buf, 1, EncOutCb);
}


void TLSCallbacks::EncOutCb(uv_write_t* req, int status) {
  HandleScope scope(node_isolate);

  TLSCallbacks* callbacks = reinterpret_cast<TLSCallbacks*>(req->data);

  // Handle error
  if (status) {
    SetErrno(uv_last_error(uv_default_loop()));
    Local<Value> arg = Integer::New(status, node_isolate);
    MakeCallback(callbacks->Self(), onerror_sym, 1, &arg);
    callbacks->InvokeQueued(status);
    return;
  }

  // Commit
  NodeBIO::FromBIO(callbacks->enc_out_)->Read(NULL, callbacks->write_size_);

  // Try writing more data
  callbacks->write_size_ = 0;
  callbacks->EncOut();
}


Handle<Value> TLSCallbacks::GetSSLError(int status, int* err) {
  HandleScope scope(node_isolate);

  *err = SSL_get_error(ssl_, status);
  switch (*err) {
   case SSL_ERROR_NONE:
   case SSL_ERROR_WANT_READ:
   case SSL_ERROR_WANT_WRITE:
    break;
   case SSL_ERROR_ZERO_RETURN:
    return scope.Close(String::NewSymbol("ZERO_RETURN"));
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

      return scope.Close(r);
    }
  }
  return Handle<Value>();
}


void TLSCallbacks::ClearOut() {
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
      MakeCallback(Self(), onread_sym, ARRAY_SIZE(argv), argv);
    }
  } while (read > 0);

  if (read == -1) {
    int err;
    Handle<Value> argv = GetSSLError(read, &err);

    if (!argv.IsEmpty())
      MakeCallback(Self(), onerror_sym, 1, &argv);
  }
}


bool TLSCallbacks::ClearIn() {
  HandleScope scope(node_isolate);

  int written = 0;
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
    MakeCallback(Self(), onerror_sym, 1, &argv);

  return false;
}


int TLSCallbacks::DoWrite(WriteWrap* w,
                          uv_buf_t* bufs,
                          int count,
                          uv_stream_t* send_handle,
                          uv_write_cb cb) {
  HandleScope scope(node_isolate);
  InitSSL();

  assert(send_handle == NULL);

  // Queue callback to execute it on next tick
  WriteItem* wi = new WriteItem(w, cb);

  // Assign handle, because AfterWrite expects it
  // XXX: handle this in stream_wrap.cc
  w->req_.handle = wrap_->GetStream();
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
      MakeCallback(Self(), onerror_sym, 1, &argv);
      return -1;
    }

    // No errors, queue rest
    for (; i < count; i++)
      clear_in_->Write(bufs[i].base, bufs[i].len);
  }

  return 0;
}


uv_buf_t TLSCallbacks::DoAlloc(uv_handle_t* handle, size_t suggested_size) {
  InitSSL();

  size_t size = suggested_size;
  char* data = NodeBIO::FromBIO(enc_in_)->Reserve(&size);
  return uv_buf_init(data, size);
}


void TLSCallbacks::DoRead(uv_stream_t* handle,
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


void TLSCallbacks::OnReadFailure(uv_buf_t buf) {
  // Ignore!
}


int TLSCallbacks::DoShutdown(ShutdownWrap* req_wrap, uv_shutdown_cb cb) {
  InitSSL();

  if (SSL_shutdown(ssl_) == 0)
    SSL_shutdown(ssl_);
  EncOut();
  return uv_shutdown(&req_wrap->req_, wrap_->GetStream(), cb);
}


void TLSCallbacks::Initialize(v8::Handle<v8::Object> target) {
  HandleScope scope(node_isolate);

  NODE_SET_METHOD(target, "wrap", TLSCallbacks::Wrap);

  onread_sym = NODE_PSYMBOL("onread");
  onerror_sym = NODE_PSYMBOL("onerror");
}


} // namespace node

NODE_MODULE(node_tls_wrap, node::TLSCallbacks::Initialize)
