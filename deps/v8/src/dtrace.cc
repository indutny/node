// Copyright 2014 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "dtrace.h"
#include "checks.h"

#include <fcntl.h>
#include <sys/dtrace.h>
#include <sys/ioctl.h>

namespace v8 {
namespace internal {

class DTraceImpl {
 public:
  DTraceImpl();

  int RegisterEnabler(byte* pc);

 private:
  int fd_;
};

static DTraceImpl impl;

DTraceImpl::DTraceImpl() {
  fd_ = open("/dev/" DTRACEMNR_HELPER, O_RDONLY);
  ASSERT(fd_ != -1 && "Failed to open DTrace helper device");
}

int DTraceImpl::RegisterEnabler(byte* pc) {
  // Prepare DOF to pass to the device
  dof_ioctl_data idof;
  dof_helper_t* helper;

  idof.dofiod_count = 1;
  helper = &idof.dofiod_helpers[0];
}

void DTrace::Relocate(byte* pc, intptr_t delta) {
  bool reinit;

#ifdef V8_TARGET_ARCH_X64
  reinit = *pc == 0x90;
  if (!reinit)
    *pc = 0x90;
#else
  abort();
#endif

  ASSERT(!reinit && "Reinit is not supported yet");
  ASSERT(impl.RegisterEnabler(pc) == 0);
}

}  // namespace internal
}  // namespace v8
