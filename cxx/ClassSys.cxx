/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#ifndef INCLUDES_cxx_Sys_cxx
#define INCLUDES_cxx_Sys_cxx
#include "Sys.hxx" /* CnsMode */
#include <vector> /* std::vector */
#include <cstdlib> /* exit EXIT_FAILURE */
#include <ctype.h> /* size_t */
#ifdef _POSIX_VERSION
#include <sys/types.h> /* pid_t */
#include <sys/wait.h> /* waitpid */
#include <unistd.h> /* execve execv fork */
#endif /* def _POSIX_VERSION */
namespace Susuwu {
const int execves(const std::vector<const std::string> &argvS, const std::vector<const std::string> &envpS) {
#ifdef _POSIX_VERSION
	pid_t pid = fork();
	if(0 != pid) {
		int status;
		assert(-1 != pid);
		waitpid(pid, &status, 0);
		return status;
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

}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_Sys_cxx */

