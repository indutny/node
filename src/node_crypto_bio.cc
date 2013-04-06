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

#include "node_crypto_bio.h"
#include "openssl/bio.h"
#include <string.h>

namespace node {

BIO_METHOD NodeBIO::method_ = {
  BIO_TYPE_MEM,
  "node.js SSL buffer",
  NodeBIO::Write,
  NodeBIO::Read,
  NodeBIO::Puts,
  NodeBIO::Gets,
  NodeBIO::Ctrl,
  NodeBIO::New,
  NodeBIO::Free,
  NULL
};


int NodeBIO::New(BIO* bio) {
  bio->ptr = new NodeBIO();

  // XXX Why am I doing it?!
  bio->shutdown = 1;
  bio->init = 1;
  bio->num = -1;

  return 1;
}


int NodeBIO::Free(BIO* bio) {
  if (bio == NULL) return 0;

  if (bio->shutdown) {
    if (bio->init && bio->ptr != NULL) {
      delete FromBIO(bio);
      bio->ptr = NULL;
    }
  }

  return 1;
}


int NodeBIO::Read(BIO* bio, char* out, int len) {
  int bytes;
  BIO_clear_retry_flags(bio);

  bytes = FromBIO(bio)->Read(out, len);

  if (bytes == 0) {
    bytes = bio->num;
    if (bytes != 0) {
      BIO_set_retry_read(bio);
    }
  }

  return bytes;
}


int NodeBIO::Write(BIO* bio, const char* data, int len) {
  BIO_clear_retry_flags(bio);

  FromBIO(bio)->Write(data, len);

  return len;
}


int NodeBIO::Puts(BIO* bio, const char* str) {
  return Write(bio, str, strlen(str));
}


int NodeBIO::Gets(BIO* bio, char* out, int size) {
  NodeBIO* nbio =  FromBIO(bio);

  if (nbio->Length() == 0)
    return 0;

  int i = nbio->IndexOf('\n', size);

  // Include '\n'
  if (i < size) i++;

  // Shift `i` a bit to NULL-terminate string later
  if (size == i) i--;

  // Flush read data
  nbio->Read(out, i);

  out[i] = 0;

  return i;
}


long NodeBIO::Ctrl(BIO* bio, int cmd, long num, void* ptr) {
  NodeBIO* nbio;
  long ret;

  nbio = FromBIO(bio);
  ret = 1;

  switch (cmd) {
   case BIO_CTRL_RESET:
    nbio->Reset();
    break;
   case BIO_CTRL_EOF:
    ret = nbio->Length() == 0;
    break;
   case BIO_C_SET_BUF_MEM_EOF_RETURN:
    bio->num = num;
    break;
   case BIO_CTRL_INFO:
    ret = nbio->Length();
    if (ptr != NULL)
      *reinterpret_cast<void**>(ptr) = NULL;
    break;
   case BIO_C_SET_BUF_MEM:
    assert(0 && "Can't use SET_BUF_MEM_PTR with NodeBIO");
    abort();
    break;
   case BIO_C_GET_BUF_MEM_PTR:
    assert(0 && "Can't use GET_BUF_MEM_PTR with NodeBIO");
    ret = 0;
    break;
   case BIO_CTRL_GET_CLOSE:
    ret = bio->shutdown;
    break;
   case BIO_CTRL_SET_CLOSE:
    bio->shutdown = num;
    break;
   case BIO_CTRL_WPENDING:
    ret = 0;
    break;
   case BIO_CTRL_PENDING:
    ret = nbio->Length();
    break;
   case BIO_CTRL_DUP:
   case BIO_CTRL_FLUSH:
    ret = 1;
    break;
   case BIO_CTRL_PUSH:
   case BIO_CTRL_POP:
   default:
    ret = 0;
    break;
  }
  return ret;
}


size_t NodeBIO::Read(char* out, size_t size) {
  size_t bytes_read = 0;
  size_t expected = Length() > size ? size : Length();
  size_t offset = 0;
  size_t left = size;

  while (bytes_read < expected) {
    assert(read_head_->read_pos_ <= read_head_->write_pos_);
    size_t avail = read_head_->write_pos_ - read_head_->read_pos_;
    if (avail > left)
      avail = left;

    // Copy data
    if (out != NULL)
      memcpy(out + offset, read_head_->data_ + read_head_->read_pos_, avail);
    read_head_->read_pos_ += avail;

    // Move pointers
    bytes_read += avail;
    offset += avail;
    left -= avail;

    // Move to next buffer
    if (read_head_->read_pos_ == read_head_->write_pos_) {
      read_head_->read_pos_ = 0;
      read_head_->write_pos_ = 0;

      // But not get beyond write_head_
      if (bytes_read != expected)
        read_head_ = read_head_->next_;
    }
  }
  assert(expected == bytes_read);
  length_ -= bytes_read;

  return bytes_read;
}


size_t NodeBIO::IndexOf(char delim, size_t limit) {
  size_t bytes_read = 0;
  size_t max = Length() > limit ? limit : Length();
  size_t left = limit;
  Buffer* current = read_head_;

  while (bytes_read < max) {
    assert(current->read_pos_ <= current->write_pos_);
    size_t avail = current->write_pos_ - current->read_pos_;
    if (avail > left)
      avail = left;

    // Walk through data
    char* tmp = current->data_ + current->read_pos_;
    size_t off = 0;
    while (off < avail && *tmp != delim) {
      off++;
      tmp++;
    }

    // Move pointers
    bytes_read += off;
    left -= off;

    // Found `delim`
    if (off != avail) {
      return bytes_read;
    }

    // Move to next buffer
    if (current->read_pos_ + avail == kBufferLength) {
      current = current->next_;
    }
  }
  assert(max == bytes_read);

  return max;
}


void NodeBIO::Write(const char* data, size_t size) {
  size_t offset = 0;
  size_t left = size;
  while (left > 0) {
    size_t to_write = left;
    assert(write_head_->write_pos_ <= kBufferLength);
    size_t avail = kBufferLength - write_head_->write_pos_;

    if (to_write > avail)
      to_write = avail;

    // Copy data
    memcpy(write_head_->data_ + write_head_->write_pos_,
           data + offset,
           to_write);

    // Move pointers
    write_head_->write_pos_ += to_write;
    left -= to_write;
    offset += to_write;
    length_ += to_write;
    assert(write_head_->write_pos_ <= kBufferLength);

    // Got to next buffer if still has some bytes to write
    if (left != 0) {
      if (write_head_->next_->write_pos_ == kBufferLength) {
        Buffer* next = new Buffer();
        next->next_ = write_head_->next_;
        write_head_->next_ = next;
      }
      write_head_ = write_head_->next_;
    }
  }
  assert(left == 0);
}


void NodeBIO::Reset() {
  while (read_head_->read_pos_ != read_head_->write_pos_) {
    assert(read_head_->write_pos_ > read_head_->read_pos_);

    length_ -= read_head_->write_pos_ - read_head_->read_pos_;
    read_head_->write_pos_ = 0;
    read_head_->read_pos_ = 0;

    read_head_ = read_head_->next_;
  }
  assert(length_ == 0);
}


NodeBIO::~NodeBIO() {
  Buffer* current = head_.next_;
  while (current != &head_) {
    Buffer* next = current->next_;
    delete current;
    current = next;
  }

  read_head_ = NULL;
  write_head_ = NULL;
}

} // namespace node
