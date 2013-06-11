#include "tls_wrap.h"
#include "node_buffer.h" // Buffer
#include "node_crypto.h" // SecureContext
#include "node_crypto_bio.h" // NodeBIO
#include "node_wrap.h" // WithGenericStream

namespace node {

using namespace v8;
using crypto::SecureContext;

static Persistent<String> onread_sym;
static Persistent<String> onsecure_sym;
static Persistent<String> onerror_sym;
static Persistent<String> onsniselect_sym;
static Persistent<String> subject_sym;
static Persistent<String> subjectaltname_sym;
static Persistent<String> modulus_sym;
static Persistent<String> exponent_sym;
static Persistent<String> issuer_sym;
static Persistent<String> valid_from_sym;
static Persistent<String> valid_to_sym;
static Persistent<String> fingerprint_sym;
static Persistent<String> name_sym;
static Persistent<String> version_sym;
static Persistent<String> ext_key_usage_sym;

static Persistent<Function> tlsWrap;

static const int X509_NAME_FLAGS = ASN1_STRFLGS_ESC_CTRL
                                 | ASN1_STRFLGS_ESC_MSB
                                 | XN_FLAG_SEP_MULTILINE
                                 | XN_FLAG_FN_SN;


TLSCallbacks::TLSCallbacks(Kind kind,
                           Handle<Object> sc,
                           StreamWrapCallbacks* old)
    : StreamWrapCallbacks(old),
      kind_(kind),
      ssl_(NULL),
      enc_in_(NULL),
      enc_out_(NULL),
      clear_in_(NULL),
      write_size_(0),
      initialized_(false) {

  // Persist SecureContext
  sc_ = ObjectWrap::Unwrap<SecureContext>(sc);
  sc_handle_ = Persistent<Object>::New(node_isolate, sc);

  handle_ = Persistent<Object>::New(node_isolate, tlsWrap->NewInstance());
  handle_->SetAlignedPointerInInternalField(0, this);

  // TODO(indutny) support it
  SSL_CTX_sess_set_get_cb(sc_->ctx_, NULL);
  SSL_CTX_sess_set_new_cb(sc_->ctx_, NULL);

  // Initialize queue for clearIn writes
  QUEUE_INIT(&write_item_queue_);
}


TLSCallbacks::~TLSCallbacks() {
  SSL_free(ssl_);
  ssl_ = NULL;
  enc_in_ = NULL;
  enc_out_ = NULL;
  delete clear_in_;
  clear_in_ = NULL;

  sc_ = NULL;
  sc_handle_.Dispose(node_isolate);
  sc_handle_.Clear();

  handle_.Dispose(node_isolate);
  handle_.Clear();

#ifdef OPENSSL_NPN_NEGOTIATED
  npn_protos_.Dispose(node_isolate);
  npn_protos_.Clear();
  selected_npn_proto_.Dispose(node_isolate);
  selected_npn_proto_.Clear();
#endif // OPENSSL_NPN_NEGOTIATED

#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  servername_.Dispose(node_isolate);
  servername_.Clear();
  sni_context_.Dispose(node_isolate);
  sni_context_.Clear();
#endif // SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
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


void TLSCallbacks::MaybeSecure() {
  if (ssl_ != NULL && !initialized_ && SSL_is_init_finished(ssl_)) {
    HandleScope scope(node_isolate);

    initialized_ = true;
    Handle<Value> argv = Boolean::New(SSL_session_reused(ssl_));
    MakeCallback(handle_, onsecure_sym, 1, &argv);
  }
}


void TLSCallbacks::InitSSL() {
  if (ssl_ != NULL)
    return;

  // Initialize SSL
  ssl_ = SSL_new(sc_->ctx_);
  enc_in_ = BIO_new(NodeBIO::GetMethod());
  enc_out_ = BIO_new(NodeBIO::GetMethod());

  SSL_set_bio(ssl_, enc_in_, enc_out_);
  if (kind_ == kTLSServer) {
    SSL_set_accept_state(ssl_);

#ifdef OPENSSL_NPN_NEGOTIATED
    // Server should advertise NPN protocols
    SSL_CTX_set_next_protos_advertised_cb(sc_->ctx_,
                                          AdvertiseNextProtoCallback,
                                          this);
#endif // OPENSSL_NPN_NEGOTIATED

#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
    SSL_CTX_set_tlsext_servername_callback(sc_->ctx_, SelectSNIContextCallback);
    SSL_CTX_set_tlsext_servername_arg(sc_->ctx_, this);
#endif // SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  } else if (kind_ == kTLSClient) {
    SSL_set_connect_state(ssl_);

#ifdef OPENSSL_NPN_NEGOTIATED
    // Client should select protocol from list of advertised
    // If server supports NPN
    SSL_CTX_set_next_proto_select_cb(sc_->ctx_,
                                     SelectNextProtoCallback,
                                     this);
#endif // OPENSSL_NPN_NEGOTIATED

#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
    String::Utf8Value servername(servername_);
    SSL_set_tlsext_host_name(ssl_, *servername);
#endif // SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  }

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

  TLSCallbacks* callbacks = NULL;
  WITH_GENERIC_STREAM(stream, {
    callbacks = new TLSCallbacks(kind, sc, wrap->GetCallbacks());
    wrap->OverrideCallbacks(callbacks);
  });

  if (callbacks == NULL)
    return Null(node_isolate);

  return scope.Close(callbacks->handle_);
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
  MaybeSecure();

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
    MakeCallback(callbacks->handle_, onerror_sym, 1, &arg);
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
      // Emit onsecure callback if its time
      MaybeSecure();
      MakeCallback(Self(), onread_sym, ARRAY_SIZE(argv), argv);
    }
  } while (read > 0);

  if (read == -1) {
    int err;
    Handle<Value> argv = GetSSLError(read, &err);

    if (!argv.IsEmpty())
      MakeCallback(handle_, onerror_sym, 1, &argv);
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
    MakeCallback(handle_, onerror_sym, 1, &argv);

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
      MakeCallback(handle_, onerror_sym, 1, &argv);
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
  return StreamWrapCallbacks::DoShutdown(req_wrap, cb);
}


Handle<Value> TLSCallbacks::VerifyError(const Arguments& args) {
  HandleScope scope(node_isolate);

  UNWRAP(TLSCallbacks);

  if (wrap->ssl_ == NULL)
    return Null(node_isolate);

  // XXX Do this check in JS land?
  X509* peer_cert = SSL_get_peer_certificate(wrap->ssl_);
  if (peer_cert == NULL) {
    // We requested a certificate and they did not send us one.
    // Definitely an error.
    // XXX is this the right error message?
    return scope.Close(Exception::Error(
          String::New("UNABLE_TO_GET_ISSUER_CERT")));
  }
  X509_free(peer_cert);

  long x509_verify_error = SSL_get_verify_result(wrap->ssl_);

  const char* reason = NULL;
  Local<String> s;
  switch (x509_verify_error) {
   case X509_V_OK:
    return Null(node_isolate);
   case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    reason = "UNABLE_TO_GET_ISSUER_CERT";
    break;
   case X509_V_ERR_UNABLE_TO_GET_CRL:
    reason = "UNABLE_TO_GET_CRL";
    break;
   case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
    reason = "UNABLE_TO_DECRYPT_CERT_SIGNATURE";
    break;
   case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
    reason = "UNABLE_TO_DECRYPT_CRL_SIGNATURE";
    break;
   case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    reason = "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
    break;
   case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    reason = "CERT_SIGNATURE_FAILURE";
    break;
   case X509_V_ERR_CRL_SIGNATURE_FAILURE:
    reason = "CRL_SIGNATURE_FAILURE";
    break;
   case X509_V_ERR_CERT_NOT_YET_VALID:
    reason = "CERT_NOT_YET_VALID";
    break;
   case X509_V_ERR_CERT_HAS_EXPIRED:
    reason = "CERT_HAS_EXPIRED";
    break;
   case X509_V_ERR_CRL_NOT_YET_VALID:
    reason = "CRL_NOT_YET_VALID";
    break;
   case X509_V_ERR_CRL_HAS_EXPIRED:
    reason = "CRL_HAS_EXPIRED";
    break;
   case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    reason = "ERROR_IN_CERT_NOT_BEFORE_FIELD";
    break;
   case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    reason = "ERROR_IN_CERT_NOT_AFTER_FIELD";
    break;
   case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    reason = "ERROR_IN_CRL_LAST_UPDATE_FIELD";
    break;
   case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
    reason = "ERROR_IN_CRL_NEXT_UPDATE_FIELD";
    break;
   case X509_V_ERR_OUT_OF_MEM:
    reason = "OUT_OF_MEM";
    break;
   case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    reason = "DEPTH_ZERO_SELF_SIGNED_CERT";
    break;
   case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    reason = "SELF_SIGNED_CERT_IN_CHAIN";
    break;
   case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    reason = "UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
    break;
   case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    reason = "UNABLE_TO_VERIFY_LEAF_SIGNATURE";
    break;
   case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    reason = "CERT_CHAIN_TOO_LONG";
    break;
   case X509_V_ERR_CERT_REVOKED:
    reason = "CERT_REVOKED";
    break;
   case X509_V_ERR_INVALID_CA:
    reason = "INVALID_CA";
    break;
   case X509_V_ERR_PATH_LENGTH_EXCEEDED:
    reason = "PATH_LENGTH_EXCEEDED";
    break;
   case X509_V_ERR_INVALID_PURPOSE:
    reason = "INVALID_PURPOSE";
    break;
   case X509_V_ERR_CERT_UNTRUSTED:
    reason = "CERT_UNTRUSTED";
    break;
   case X509_V_ERR_CERT_REJECTED:
    reason = "CERT_REJECTED";
    break;
   default:
    s = String::New(X509_verify_cert_error_string(x509_verify_error));
    break;
  }

  if (s.IsEmpty()) {
    s = String::New(reason);
  }

  return scope.Close(Exception::Error(s));
}


Handle<Value> TLSCallbacks::GetPeerCertificate(const Arguments& args) {
  HandleScope scope(node_isolate);

  UNWRAP(TLSCallbacks);

  if (wrap->ssl_ == NULL)
    return Undefined(node_isolate);

  Local<Object> info = Object::New();
  X509* peer_cert = SSL_get_peer_certificate(wrap->ssl_);
  if (peer_cert != NULL) {
    BIO* bio = BIO_new(BIO_s_mem());
    BUF_MEM* mem;
    if (X509_NAME_print_ex(bio,
                           X509_get_subject_name(peer_cert),
                           0,
                           X509_NAME_FLAGS) > 0) {
      BIO_get_mem_ptr(bio, &mem);
      info->Set(subject_sym, String::New(mem->data, mem->length));
    }
    (void) BIO_reset(bio);

    if (X509_NAME_print_ex(bio,
                           X509_get_issuer_name(peer_cert),
                           0,
                           X509_NAME_FLAGS) > 0) {
      BIO_get_mem_ptr(bio, &mem);
      info->Set(issuer_sym, String::New(mem->data, mem->length));
    }
    (void) BIO_reset(bio);

    int index = X509_get_ext_by_NID(peer_cert, NID_subject_alt_name, -1);
    if (index >= 0) {
      X509_EXTENSION* ext;
      int rv;

      ext = X509_get_ext(peer_cert, index);
      assert(ext != NULL);

      rv = X509V3_EXT_print(bio, ext, 0, 0);
      assert(rv == 1);

      BIO_get_mem_ptr(bio, &mem);
      info->Set(subjectaltname_sym, String::New(mem->data, mem->length));

      (void) BIO_reset(bio);
    }

    EVP_PKEY* pkey = NULL;
    RSA* rsa = NULL;
    if (NULL != (pkey = X509_get_pubkey(peer_cert)) &&
        NULL != (rsa = EVP_PKEY_get1_RSA(pkey))) {
      BN_print(bio, rsa->n);
      BIO_get_mem_ptr(bio, &mem);
      info->Set(modulus_sym, String::New(mem->data, mem->length) );
      (void) BIO_reset(bio);

      BN_print(bio, rsa->e);
      BIO_get_mem_ptr(bio, &mem);
      info->Set(exponent_sym, String::New(mem->data, mem->length) );
      (void) BIO_reset(bio);
    }

    if (pkey != NULL) {
      EVP_PKEY_free(pkey);
      pkey = NULL;
    }
    if (rsa != NULL) {
      RSA_free(rsa);
      rsa = NULL;
    }

    ASN1_TIME_print(bio, X509_get_notBefore(peer_cert));
    BIO_get_mem_ptr(bio, &mem);
    info->Set(valid_from_sym, String::New(mem->data, mem->length));
    (void) BIO_reset(bio);

    ASN1_TIME_print(bio, X509_get_notAfter(peer_cert));
    BIO_get_mem_ptr(bio, &mem);
    info->Set(valid_to_sym, String::New(mem->data, mem->length));
    BIO_free_all(bio);

    unsigned int md_size, i;
    unsigned char md[EVP_MAX_MD_SIZE];
    if (X509_digest(peer_cert, EVP_sha1(), md, &md_size)) {
      const char hex[] = "0123456789ABCDEF";
      char fingerprint[EVP_MAX_MD_SIZE * 3];

      for (i = 0; i<md_size; i++) {
        fingerprint[3*i] = hex[(md[i] & 0xf0) >> 4];
        fingerprint[(3*i)+1] = hex[(md[i] & 0x0f)];
        fingerprint[(3*i)+2] = ':';
      }

      if (md_size > 0)
        fingerprint[(3*(md_size-1))+2] = '\0';
      else
        fingerprint[0] = '\0';

      info->Set(fingerprint_sym, String::New(fingerprint));
    }

    STACK_OF(ASN1_OBJECT)* eku = reinterpret_cast<STACK_OF(ASN1_OBJECT)*>(
        X509_get_ext_d2i(peer_cert,
                         NID_ext_key_usage,
                         NULL,
                         NULL));
    if (eku != NULL) {
      Local<Array> ext_key_usage = Array::New();
      char buf[256];

      for (int i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
        memset(buf, 0, sizeof(buf));
        OBJ_obj2txt(buf, sizeof(buf) - 1, sk_ASN1_OBJECT_value(eku, i), 1);
        ext_key_usage->Set(Integer::New(i, node_isolate), String::New(buf));
      }

      sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
      info->Set(ext_key_usage_sym, ext_key_usage);
    }

    X509_free(peer_cert);
  }

  return scope.Close(info);
}


Handle<Value> TLSCallbacks::GetSession(const Arguments& args) {
  HandleScope scope(node_isolate);

  UNWRAP(TLSCallbacks);

  if (wrap->ssl_ == NULL)
    return Undefined(node_isolate);

  SSL_SESSION* sess = SSL_get_session(wrap->ssl_);
  if (!sess)
    return Undefined(node_isolate);

  int slen = i2d_SSL_SESSION(sess, NULL);
  assert(slen > 0);

  if (slen > 0) {
    unsigned char* sbuf = new unsigned char[slen];
    unsigned char* p = sbuf;
    i2d_SSL_SESSION(sess, &p);
    Local<Value> s = Encode(sbuf, slen, BUFFER);
    delete[] sbuf;
    return scope.Close(s);
  }

  return Null(node_isolate);
}


Handle<Value> TLSCallbacks::SetSession(const Arguments& args) {
  HandleScope scope(node_isolate);

  UNWRAP(TLSCallbacks);

  if (args.Length() < 1 ||
      (!args[0]->IsString() && !Buffer::HasInstance(args[0]))) {
    return ThrowTypeError("Bad argument");
  }

  ssize_t slen = Buffer::Length(args[0]);

  if (slen < 0)
    return ThrowTypeError("Bad argument");

  char* sbuf = new char[slen];

  ssize_t wlen = DecodeWrite(sbuf, slen, args[0], BINARY);
  assert(wlen == slen);

  const unsigned char* p = reinterpret_cast<const unsigned char*>(sbuf);
  SSL_SESSION* sess = d2i_SSL_SESSION(NULL, &p, wlen);

  delete [] sbuf;

  if (!sess)
    return Undefined(node_isolate);

  int r = SSL_set_session(wrap->ssl_, sess);
  SSL_SESSION_free(sess);

  if (!r) {
    Local<String> eStr = String::New("SSL_set_session error");
    return ThrowException(Exception::Error(eStr));
  }

  return True(node_isolate);
}


Handle<Value> TLSCallbacks::GetCurrentCipher(const Arguments& args) {
  HandleScope scope(node_isolate);

  UNWRAP(TLSCallbacks);

  const SSL_CIPHER* c;

  if (wrap->ssl_ == NULL)
    return Undefined(node_isolate);

  c = SSL_get_current_cipher(wrap->ssl_);
  if (c == NULL)
    return Undefined(node_isolate);

  const char* cipher_name = SSL_CIPHER_get_name(c);
  const char* cipher_version = SSL_CIPHER_get_version(c);

  Local<Object> info = Object::New();
  info->Set(name_sym, String::New(cipher_name));
  info->Set(version_sym, String::New(cipher_version));
  return scope.Close(info);
}


#ifdef OPENSSL_NPN_NEGOTIATED
int TLSCallbacks::AdvertiseNextProtoCallback(SSL* s,
                                             const unsigned char** data,
                                             unsigned int* len,
                                             void* arg) {
  TLSCallbacks* p = static_cast<TLSCallbacks*>(arg);

  if (p->npn_protos_.IsEmpty()) {
    // No initialization - no NPN protocols
    *data = reinterpret_cast<const unsigned char*>("");
    *len = 0;
  } else {
    *data = reinterpret_cast<const unsigned char*>(
        Buffer::Data(p->npn_protos_));
    *len = Buffer::Length(p->npn_protos_);
  }

  return SSL_TLSEXT_ERR_OK;
}


int TLSCallbacks::SelectNextProtoCallback(SSL* s,
                                          unsigned char** out,
                                          unsigned char* outlen,
                                          const unsigned char* in,
                                          unsigned int inlen,
                                          void* arg) {
  TLSCallbacks* p = static_cast<TLSCallbacks*>(arg);

  // Release old protocol handler if present
  if (!p->selected_npn_proto_.IsEmpty()) {
    p->selected_npn_proto_.Dispose(node_isolate);
  }

  if (p->npn_protos_.IsEmpty()) {
    // We should at least select one protocol
    // If server is using NPN
    *out = reinterpret_cast<unsigned char*>(const_cast<char*>("http/1.1"));
    *outlen = 8;

    // set status: unsupported
    p->selected_npn_proto_ = Persistent<Value>::New(node_isolate,
                                                    False(node_isolate));

    return SSL_TLSEXT_ERR_OK;
  }

  const unsigned char* npn_protos =
      reinterpret_cast<const unsigned char*>(Buffer::Data(p->npn_protos_));
  size_t len = Buffer::Length(p->npn_protos_);

  int status = SSL_select_next_proto(out, outlen, in, inlen, npn_protos, len);
  Handle<Value> result;
  switch (status) {
   case OPENSSL_NPN_UNSUPPORTED:
    result = Null(node_isolate);
    break;
   case OPENSSL_NPN_NEGOTIATED:
    result = String::New(reinterpret_cast<const char*>(*out), *outlen);
    break;
   case OPENSSL_NPN_NO_OVERLAP:
    result = False(node_isolate);
    break;
   default:
    break;
  }

  if (!result.IsEmpty())
    p->selected_npn_proto_ = Persistent<Value>::New(node_isolate, result);

  return SSL_TLSEXT_ERR_OK;
}


Handle<Value> TLSCallbacks::GetNegotiatedProto(const Arguments& args) {
  HandleScope scope(node_isolate);

  UNWRAP(TLSCallbacks);

  if (wrap->kind_ == kTLSClient) {
    if (wrap->selected_npn_proto_.IsEmpty())
      return Undefined(node_isolate);
    else
      return wrap->selected_npn_proto_;
  }

  const unsigned char* npn_proto;
  unsigned int npn_proto_len;

  SSL_get0_next_proto_negotiated(wrap->ssl_, &npn_proto, &npn_proto_len);

  if (!npn_proto)
    return False(node_isolate);

  return scope.Close(String::New(reinterpret_cast<const char*>(npn_proto),
                                 npn_proto_len));
}


Handle<Value> TLSCallbacks::SetNPNProtocols(const Arguments& args) {
  HandleScope scope(node_isolate);

  UNWRAP(TLSCallbacks);

  if (args.Length() < 1 || !Buffer::HasInstance(args[0]))
    return ThrowTypeError("Must give a Buffer as first argument");

  // Release old handle
  if (!wrap->npn_protos_.IsEmpty())
    wrap->npn_protos_.Dispose(node_isolate);

  wrap->npn_protos_ =
      Persistent<Object>::New(node_isolate, args[0]->ToObject());

  return True(node_isolate);
}
#endif // OPENSSL_NPN_NEGOTIATED


#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
Handle<Value> TLSCallbacks::GetServerName(const Arguments& args) {
  HandleScope scope(node_isolate);

  UNWRAP(TLSCallbacks);

  if (wrap->kind_ == kTLSServer && !wrap->servername_.IsEmpty()) {
    return wrap->servername_;
  } else {
    return False(node_isolate);
  }
}


int TLSCallbacks::SelectSNIContextCallback(SSL* s, int* ad, void* arg) {
  HandleScope scope(node_isolate);

  TLSCallbacks* p = static_cast<TLSCallbacks*>(arg);

  const char* servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);

  if (servername) {
    if (!p->servername_.IsEmpty())
      p->servername_.Dispose(node_isolate);
    p->servername_ = Persistent<String>::New(node_isolate,
                                             String::New(servername));

    // Call the SNI callback and use its return value as context
    if (p->handle_->Has(onsniselect_sym)) {
      if (!p->sni_context_.IsEmpty())
        p->sni_context_.Dispose(node_isolate);

      // Get callback init args
      Local<Value> argv[1] = {*p->servername_};

      // Call it
      Local<Value> ret = Local<Value>::New(node_isolate,
                                           MakeCallback(p->handle_,
                                                        onsniselect_sym,
                                                        ARRAY_SIZE(argv),
                                                        argv));

      // If ret is SecureContext
      if (!ret->IsFalse())
        return SSL_TLSEXT_ERR_NOACK;

      p->sni_context_ = Persistent<Value>::New(node_isolate, ret);
      SecureContext* sc = ObjectWrap::Unwrap<SecureContext>(ret.As<Object>());
      SSL_set_SSL_CTX(s, sc->ctx_);
    }
  }

  return SSL_TLSEXT_ERR_OK;
}
#endif // SSL_CTRL_SET_TLSEXT_SERVERNAME_CB


void TLSCallbacks::Initialize(Handle<Object> target) {
  HandleScope scope(node_isolate);

  NODE_SET_METHOD(target, "wrap", TLSCallbacks::Wrap);

  Local<FunctionTemplate> t = FunctionTemplate::New();
  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewSymbol("TLSWrap"));

  NODE_SET_PROTOTYPE_METHOD(t, "getPeerCertificate", GetPeerCertificate);
  NODE_SET_PROTOTYPE_METHOD(t, "getSession", GetSession);
  NODE_SET_PROTOTYPE_METHOD(t, "setSession", SetSession);
  NODE_SET_PROTOTYPE_METHOD(t, "getCurrentCipher", GetCurrentCipher);
  NODE_SET_PROTOTYPE_METHOD(t, "verifyError", VerifyError);

#ifdef OPENSSL_NPN_NEGOTIATED
  NODE_SET_PROTOTYPE_METHOD(t, "getNegotiatedProtocol", GetNegotiatedProto);
  NODE_SET_PROTOTYPE_METHOD(t, "setNPNProtocols", SetNPNProtocols);
#endif // OPENSSL_NPN_NEGOTIATED

#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  NODE_SET_PROTOTYPE_METHOD(t, "getServername", GetServerName);
#endif // SSL_CRT_SET_TLSEXT_SERVERNAME_CB

  tlsWrap = Persistent<Function>::New(node_isolate, t->GetFunction());

  onread_sym = NODE_PSYMBOL("onread");
  onsecure_sym = NODE_PSYMBOL("onsecure");
  onsniselect_sym = NODE_PSYMBOL("onsniselect");
  onerror_sym = NODE_PSYMBOL("onerror");

  subject_sym = NODE_PSYMBOL("subject");
  issuer_sym = NODE_PSYMBOL("issuer");
  valid_from_sym = NODE_PSYMBOL("valid_from");
  valid_to_sym = NODE_PSYMBOL("valid_to");
  subjectaltname_sym = NODE_PSYMBOL("subjectaltname");
  modulus_sym = NODE_PSYMBOL("modulus");
  exponent_sym = NODE_PSYMBOL("exponent");
  fingerprint_sym = NODE_PSYMBOL("fingerprint");
  name_sym = NODE_PSYMBOL("name");
  version_sym = NODE_PSYMBOL("version");
  ext_key_usage_sym = NODE_PSYMBOL("ext_key_usage");
}


} // namespace node

NODE_MODULE(node_tls_wrap, node::TLSCallbacks::Initialize)
