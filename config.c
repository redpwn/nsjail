/*

   nsjail - config parsing
   -----------------------------------------

   Copyright 2017 Google Inc. All Rights Reserved.

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

#include "common.h"

#include <stdio.h>
#include <sys/personality.h>

#include "config.h"
#include "log.h"
#include "user.h"
#include "util.h"

#if !defined(NSJAIL_WITH_PROTOBUF)
bool configParse(struct nsjconf_t * nsjconf UNUSED, const char *file UNUSED)
{
	LOG_W("nsjail was not compiled with the protobuf-c library");
	return false;
}
#else				/* !defined(NSJAIL_WITH_PROTOBUF) */

#include "config.pb-c.h"
#include "protobuf-c-text.h"

static bool configParseInternal(struct nsjconf_t *nsjconf, Nsjail__NsJailConfig * njc)
{
	switch (njc->mode) {
	case NSJAIL__MODE__LISTEN:
		nsjconf->mode = MODE_LISTEN_TCP;
		break;
	case NSJAIL__MODE__ONCE:
		nsjconf->mode = MODE_STANDALONE_ONCE;
		break;
	case NSJAIL__MODE__RERUN:
		nsjconf->mode = MODE_STANDALONE_RERUN;
		break;
	case NSJAIL__MODE__EXECVE:
		nsjconf->mode = MODE_STANDALONE_EXECVE;
		break;
	default:
		LOG_E("Uknown running mode: %d", njc->mode);
		return false;
	}
	if (njc->has_chroot_dir) {
		nsjconf->chroot = utilStrDupLen((char *)njc->chroot_dir.data, njc->chroot_dir.len);
	}
	nsjconf->hostname = utilStrDupLen((char *)njc->hostname.data, njc->hostname.len);
	nsjconf->cwd = utilStrDupLen((char *)njc->cwd.data, njc->cwd.len);
	nsjconf->bindhost = utilStrDupLen((char *)njc->bindhost.data, njc->bindhost.len);
	nsjconf->max_conns_per_ip = njc->max_conns_per_ip;
	nsjconf->tlimit = njc->time_limit;
	nsjconf->daemonize = njc->daemon;

	if (njc->has_log_file) {
		nsjconf->logfile = utilStrDupLen((char *)njc->log_file.data, njc->log_file.len);
	}
	if (njc->has_log_level) {
		switch (njc->log_level) {
		case NSJAIL__LOG_LEVEL__DEBUG:
			nsjconf->loglevel = DEBUG;
			break;
		case NSJAIL__LOG_LEVEL__INFO:
			nsjconf->loglevel = INFO;
			break;
		case NSJAIL__LOG_LEVEL__WARNING:
			nsjconf->loglevel = WARNING;
			break;
		case NSJAIL__LOG_LEVEL__ERROR:
			nsjconf->loglevel = ERROR;
			break;
		case NSJAIL__LOG_LEVEL__FATAL:
			nsjconf->loglevel = FATAL;
			break;
		default:
			LOG_E("Unknown log_level: %d", njc->log_level);
			return false;
		}

	}

	if (njc->has_log_file || njc->has_log_level) {
		if (logInitLogFile(nsjconf) == false) {
			return false;
		}
	}

	nsjconf->keep_env = njc->keep_env;
	nsjconf->is_silent = njc->silent;
	nsjconf->skip_setsid = njc->skip_setsid;

	for (size_t i = 0; i < njc->n_pass_fd; i++) {
		struct fds_t *f = utilMalloc(sizeof(struct fds_t));
		f->fd = njc->pass_fd[i];
		TAILQ_INSERT_HEAD(&nsjconf->open_fds, f, pointers);
	}

	nsjconf->pivot_root_only = njc->pivot_root_only;
	nsjconf->disable_no_new_privs = njc->disable_no_new_privs;

	nsjconf->rl_as = njc->rlimit_as * 1024ULL * 1024ULL;
	nsjconf->rl_core = njc->rlimit_core * 1024ULL * 1024ULL;
	nsjconf->rl_cpu = njc->rlimit_cpu;
	nsjconf->rl_fsize = njc->rlimit_fsize * 1024ULL * 1024ULL;
	nsjconf->rl_nofile = njc->rlimit_nofile;
	if (njc->has_rlimit_nproc) {
		nsjconf->rl_nproc = njc->rlimit_nproc;
	}
	if (njc->has_rlimit_stack) {
		nsjconf->rl_stack = njc->rlimit_stack * 1024ULL * 1024ULL;
	}

	if (njc->persona_addr_compat_layout) {
		nsjconf->personality |= ADDR_COMPAT_LAYOUT;
	}
	if (njc->persona_mmap_page_zero) {
		nsjconf->personality |= MMAP_PAGE_ZERO;
	}
	if (njc->persona_read_implies_exec) {
		nsjconf->personality |= READ_IMPLIES_EXEC;
	}
	if (njc->persona_addr_limit_3gb) {
		nsjconf->personality |= ADDR_LIMIT_3GB;
	}
	if (njc->persona_addr_no_randomize) {
		nsjconf->personality |= ADDR_NO_RANDOMIZE;
	}

	nsjconf->clone_newnet = njc->clone_newnet;
	nsjconf->clone_newuser = njc->clone_newuser;
	nsjconf->clone_newns = njc->clone_newns;
	nsjconf->clone_newpid = njc->clone_newpid;
	nsjconf->clone_newipc = njc->clone_newipc;
	nsjconf->clone_newuts = njc->clone_newuts;
	nsjconf->clone_newcgroup = njc->clone_newcgroup;

	for (size_t i = 0; i < njc->n_uidmap; i++) {
		const char *i_id =
		    utilStrDupLen((char *)njc->uidmap[i]->inside_id.data,
				  njc->uidmap[i]->inside_id.len);
		const char *o_id =
		    utilStrDupLen((char *)njc->uidmap[i]->outside_id.data,
				  njc->uidmap[i]->outside_id.len);
		struct idmap_t *p =
		    userParseId(i_id, o_id, njc->uidmap[i]->count, false /* is_gid */ );
		if (p == NULL) {
			return false;
		}
		TAILQ_INSERT_TAIL(&nsjconf->uids, p, pointers);
	}
	for (size_t i = 0; i < njc->n_gidmap; i++) {
		const char *i_id =
		    utilStrDupLen((char *)njc->gidmap[i]->inside_id.data,
				  njc->uidmap[i]->inside_id.len);
		const char *o_id =
		    utilStrDupLen((char *)njc->gidmap[i]->outside_id.data,
				  njc->uidmap[i]->outside_id.len);
		struct idmap_t *p =
		    userParseId(i_id, o_id, njc->gidmap[i]->count, true /* is_gid */ );
		if (p == NULL) {
			return false;
		}
		TAILQ_INSERT_TAIL(&nsjconf->gids, p, pointers);
	}
	for (size_t i = 0; i < njc->n_newuidmap; i++) {
		const char *i_id =
		    utilStrDupLen((char *)njc->newuidmap[i]->inside_id.data,
				  njc->uidmap[i]->inside_id.len);
		const char *o_id =
		    utilStrDupLen((char *)njc->newuidmap[i]->outside_id.data,
				  njc->uidmap[i]->outside_id.len);
		struct idmap_t *p =
		    userParseId(i_id, o_id, njc->newuidmap[i]->count, false /* is_gid */ );
		if (p == NULL) {
			return false;
		}
		TAILQ_INSERT_TAIL(&nsjconf->newuidmap, p, pointers);
	}

	for (size_t i = 0; i < njc->n_newgidmap; i++) {
		const char *i_id =
		    utilStrDupLen((char *)njc->newgidmap[i]->inside_id.data,
				  njc->uidmap[i]->inside_id.len);
		const char *o_id =
		    utilStrDupLen((char *)njc->newgidmap[i]->outside_id.data,
				  njc->uidmap[i]->outside_id.len);
		struct idmap_t *p =
		    userParseId(i_id, o_id, njc->newgidmap[i]->count, true /* is_gid */ );
		if (p == NULL) {
			return false;
		}
		TAILQ_INSERT_TAIL(&nsjconf->newgidmap, p, pointers);
	}

	return true;
}

bool configParse(struct nsjconf_t * nsjconf, const char *file)
{
	LOG_I("Parsing configuration from '%s'", file);

	FILE *f = fopen(file, "rb");
	if (f == NULL) {
		PLOG_W("Couldn't open '%s' for reading", file);
		return false;
	}

	ProtobufCTextError error;
	Nsjail__NsJailConfig *njc =
	    (Nsjail__NsJailConfig *) protobuf_c_text_from_file(&nsjail__ns_jail_config__descriptor,
							       f, &error, NULL);
	if (njc == NULL) {
		LOG_W("Couldn't parse config from '%s': %s", file, error.error_txt);
		fclose(f);
		return false;
	}

	bool ret = configParseInternal(nsjconf, njc);

	char *config_str = protobuf_c_text_to_string((ProtobufCMessage *) njc, NULL);
	if (config_str) {
		LOG_D("Parsed config:\n%s", config_str);
		free(config_str);
	}

	fclose(f);
	return ret;
}
#endif				/* !defined(NSJAIL_WITH_PROTOBUF) */
