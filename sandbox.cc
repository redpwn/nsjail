/*

   nsjail - seccomp-bpf sandboxing
   -----------------------------------------

   Copyright 2014 Google Inc. All Rights Reserved.

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

#include "sandbox.h"

#include <sched.h>
#include <seccomp.h>

#include <memory>

#include "logs.h"

namespace {

// Simplified version of std::unique_ptr constructor with deleter for type
// inference
template <typename T, typename D>
inline std::unique_ptr<T, D> unique_ptr_with_deleter(T* ptr, D deleter) {
	return std::unique_ptr<T, D>{ptr, deleter};
}

};  // namespace

namespace sandbox {

static bool prepareAndCommit(nsjconf_t* nsjconf) {
	if (seccomp_load(nsjconf->seccomp_ctx)) {
		PLOG_W("seccomp_load() failed");
		return false;
	}
	return true;
}

bool applyPolicy(nsjconf_t* nsjconf) {
	return prepareAndCommit(nsjconf);
}

bool preparePolicy(nsjconf_t* nsjconf) {
	auto seccomp_ctx = unique_ptr_with_deleter(seccomp_init(SCMP_ACT_ALLOW), &seccomp_release);
	if (!seccomp_ctx) {
		PLOG_E("seccomp_init() failed");
		return false;
	}

	auto arch = seccomp_arch_native();
	if (arch == SCMP_ARCH_X86_64) {
		if (seccomp_arch_add(seccomp_ctx.get(), SCMP_ARCH_X86)) {
			PLOG_E("seccomp_arch_add(SCMP_ARCH_X86) failed");
			return false;
		}
	} else if (arch == SCMP_ARCH_AARCH64) {
		if (seccomp_arch_add(seccomp_ctx.get(), SCMP_ARCH_ARM)) {
			PLOG_E("seccomp_arch_add(SCMP_ARCH_ARM) failed");
			return false;
		}
	} else {
		PLOG_E("native arch is not amd64 or arm64");
		return false;
	}

	for (int sys :
	    {SCMP_SYS(mount), SCMP_SYS(sethostname), SCMP_SYS(umount2), SCMP_SYS(pivot_root)}) {
		if (seccomp_rule_add(seccomp_ctx.get(), SCMP_ACT_ERRNO(EPERM), sys, 0)) {
			PLOG_E("seccomp_rule_add() failed");
			return false;
		}
	}

	for (scmp_datum_t flag : {CLONE_NEWNS, CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC,
		 CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET}) {
		if (seccomp_rule_add(seccomp_ctx.get(), SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
			SCMP_A0_64(SCMP_CMP_MASKED_EQ, flag, flag))) {
			PLOG_E("seccomp_rule_add(clone) failed");
			return false;
		}
	}

	nsjconf->seccomp_ctx = seccomp_ctx.release();
	return true;
}

void closePolicy(nsjconf_t* nsjconf) {
	seccomp_release(nsjconf->seccomp_ctx);
	nsjconf->seccomp_ctx = nullptr;
}

}  // namespace sandbox
