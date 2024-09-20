/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#ifndef INCLUDES_cxx_ClassSys_cxx
#define INCLUDES_cxx_ClassSys_cxx
#include "ClassSys.hxx" /* std::string std::vector */
#include <cassert> /* assert */
#include <cstdlib> /* atoi exit EXIT_FAILURE getenv */
#include <iostream> /* std::cerr std::endl */
#ifdef _POSIX_VERSION
#include <stdexcept> /* std::runtime_error */
#include <sys/types.h> /* pid_t */
#include <sys/wait.h> /* waitpid */
#include <unistd.h> /* execve execv fork geteuid getuid setuid */
#else
# ifdef __WIN32__
# include <shlobj_core.h> /* IsUserAnAdmin */
# endif /* def __WIN32__ */
typedef int pid_t;
#endif /* def _POSIX_VERSION */
namespace Susuwu {
const pid_t execvesFork(const std::vector<const std::string> &argvS, const std::vector<const std::string> &envpS) {
#ifdef _POSIX_VERSION
	const pid_t pid = fork();
	if(0 != pid) {
		int status;
		assert(-1 != pid);
		return pid;
	} /* if 0, is fork */
	const std::vector<std::string> argvSmutable = {argvS.cbegin(), argvS.cend()};
	std::vector<char *> argv;
	//for(auto x : argvSmutable) { /* with `fsanitize=address` this triggers "stack-use-after-scope" */
	for(auto x = argvSmutable.begin(); argvSmutable.end() != x; ++x) {
		argv.push_back(const_cast<char *>(x->c_str()));
	}
	argv.push_back(NULL);
	if(envpS.empty()) { /* Reuse LD_PRELOAD to fix https://github.com/termux-play-store/termux-issues/issues/24 */
		execv(argv[0], &argv[0]); /* NORETURN */
	} else {
		std::vector<std::string> envpSmutable = {envpS.cbegin(), envpS.cend()};
		std::vector<char *> envp;
		for(auto x = envpSmutable.begin(); envpSmutable.end() != x; ++x) {
			envp.push_back(const_cast<char *>(x->c_str()));
		}
		envp.push_back(NULL);
		execve(argv[0], &argv[0], &envp[0]); /* NORETURN */
	}
	exit(EXIT_FAILURE); /* execv*() is NORETURN */
#endif /* def _POSIX_VERSION */
}
const int execves(const std::vector<const std::string> &argvS, const std::vector<const std::string> &envpS) {
#ifdef _POSIX_VERSION
	const pid_t pid = execvesFork(argvS, envpS);
	int status;
	waitpid(pid, &status, 0);
	return status;
#endif /* _POSIX_VERSION */
}

const bool hasRoot() {
#ifdef _POSIX_VERSION
	return (0 == geteuid());
#elif defined __WIN32__
	return IsUserAnAdmin();
#else
	std::cerr << "[`hasRoot(bool)`: Warning: `#if !(defined _POSIX_VERSION || defined __WIN32__)`; TODO]" << std::endl;
	return false;
#endif /* def _POSIX_VERSION or def __WIN32__ */
}
const bool setRoot(bool root) {
	if(hasRoot() == root) {
		return root;
	}
#ifdef _POSIX_VERSION
	if(root) {
		if(-1 == seteuid(0)) {
			std::cerr << "[Warning: `setRoot(true)`: `(-1 == seteuid(0))` (stuck as user, perhaps is not setuid executable)]" << std::endl;
		}
#if 0
# ifdef __APPLE__ //TODO: https://stackoverflow.com/questions/2483755/how-to-programmatically-gain-root-privileges/35316538#35316538 says you must execute new processes to do this
# else //TODO: https://stackoverflow.com/questions/34723861/calling-a-c-function-with-root-privileges-without-executing-the-whole-program/70149223#70149223 https://stackoverflow.com/questions/70615937/how-to-run-a-command-as-root-with-c-or-c-with-no-pam-in-linux-with-password-au https://stackoverflow.com/questions/2483755/how-to-programmatically-gain-root-privileges/2483789#2483789 says you must spawn new processes to do this
		/* TODO: polkit? Until this is finished, you must use chmod (to give setuid to executable), or execute new processes (with `sudo`/`su`) if you wish to use firewall/antivirus (which require root) */
# endif /* __APPLE__ else */
#endif /* 0 */
	} else {
/* # ifdef LINUX // TODO: pam_loginuid.so(8) // https://stackoverflow.com/questions/10272784/how-do-i-get-the-users-real-uid-if-the-program-is-run-with-sudo/10272881#10272881
		uid_t sudo_uid = audit_getloginuid();
# else */
		uid_t sudo_uid = getuid();
		if(0 == sudo_uid) {
			char *sudo_uid_str = getenv("SUDO_UID");
			if(NULL == sudo_uid_str) {
				std::cerr << "[Warning: `setRoot(false)`: `NULL == getenv(\"SUDO_UID\")` (stuck as root)]" << std::endl;
				return true;
			} else {
				sudo_uid = (uid_t)atoi(sudo_uid_str);
				if(-1 == setuid(sudo_uid)) { /* prevent reescalation to root */
					std::cerr << "[Warning: `setRoot(false)`: `(-1 == setuid(sudo_uid))` (can't prevent reescalation to root)]" << std::endl;
				}
			}
		}
//# endif /* def LINUX */
		if(0 == sudo_uid) {
			std::cerr << "[Warning: `setRoot(false)`: `0 == sudo_uid` (stuck as root)]" << std::endl;
		} else if(-1 == seteuid(sudo_uid)) {
			std::cerr << "[Warning: `setRoot(false)`: `(-1 == seteuid(sudo_uid))` (stuck as root)]" << std::endl;
		}
	}
/* #elif defined __WIN32__ *///TODO: https://stackoverflow.com/questions/6418791/requesting-administrator-privileges-at-run-time says you must spawn new processes to do this
#else
	std::cerr << "[Warning: `setRoot(bool)`: `#ifndef _POSIX_VERSION`; TODO]" << std::endl;
#endif /* _POSIX_VERSION */
	return hasRoot();
}

}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassSys_cxx */

