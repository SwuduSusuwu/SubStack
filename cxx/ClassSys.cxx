/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#ifndef INCLUDES_cxx_ClassSys_cxx
#define INCLUDES_cxx_ClassSys_cxx
#include "ClassSys.hxx" /* std::string std::vector */
#include <cassert> /* assert */
#include <cstdlib> /* exit EXIT_FAILURE */
#ifdef _POSIX_VERSION
#include <sys/types.h> /* pid_t */
#include <sys/wait.h> /* waitpid */
#include <unistd.h> /* execve execv fork */
#else
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

}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassSys_cxx */

