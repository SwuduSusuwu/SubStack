/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#ifndef INCLUDES_cxx_ClassSys_cxx
#define INCLUDES_cxx_ClassSys_cxx
#include "Macros.hxx" /* ERROR SUSUWU_PRINT SUSUWU_ERRSTR WARNING */
#include "ClassSys.hxx" /* std::string std::to_string std::vector */
#include <cassert> /* assert */
#include <cstdlib> /* exit EXIT_FAILURE EXIT_SUCCESS getenv strtol */
#include <iostream> /* std::cerr std::cout std::endl std::flush std::ios::eofbit std::ios::goodbit */
#ifdef _POSIX_VERSION
#include <stdexcept> /* std::runtime_error */
#include <sys/types.h> /* pid_t */
#include <sys/wait.h> /* waitpid */
#include <unistd.h> /* execve execv fork geteuid getuid setuid */
#else
# ifdef __WIN32__
# include <shlobj.h> /* IsUserAnAdmin */
# endif /* def __WIN32__ */
typedef int pid_t;
#endif /* def _POSIX_VERSION */
namespace Susuwu {
int classSysArgc = 0;
const char **classSysArgs = {nullptr};
const bool classSysInit(int argc, const char *args[]) {
	if(0 < (classSysArgc = argc)) {
		classSysArgs = args;
		assert(nullptr != args);
		assert(nullptr != args[0]);
		return true;
	}
	return false;
}

const pid_t execvesFork(const std::vector<std::string> &argvS, const std::vector<std::string> &envpS) {
#ifdef _POSIX_VERSION
	const pid_t pid = fork();
	if(0 != pid) {
		if(-1 == pid) {
			std::string error = "execvesFork(): {(-1 == pid)}, errno=" + std::to_string(errno);
			SUSUWU_ERROR(error);
			throw std::runtime_error(error);
		}
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
#else /* ndef _POSIX_VERSION */
# undef ERROR /* undo `shlobj.h`'s `#define ERROR 0` */
	throw std::runtime_error(SUSUWU_ERRSTR(ERROR, "execvesFork: {#ifndef _POSIX_VERSION /* TODO: convert to win32 */}"));
#endif /* ndef _POSIX_VERSION */
}
const int execves(const std::vector<std::string> &argvS, const std::vector<std::string> &envpS) {
#ifdef _POSIX_VERSION
	const pid_t pid = execvesFork(argvS, envpS);
	int status;
	waitpid(pid, &status, 0);
	return status;
#else /* ndef _POSIX_VERSION */
	throw std::runtime_error(SUSUWU_ERRSTR(ERROR, "execves: {#ifndef _POSIX_VERSION /* TODO: convert to win32 */}"));
# define ERROR 0 /* redo `shlobj.h`'s `#define ERROR 0` */
#endif /* ndef _POSIX_VERSION */
}

const bool classSysHasRoot() {
#ifdef _POSIX_VERSION
	return (0 == geteuid());
#elif defined __WIN32__
	return IsUserAnAdmin();
#else
	SUSUWU_PRINT(WARNING, "classSysHasRoot(bool) {#if !(defined _POSIX_VERSION || defined __WIN32__) /* TODO */}");
	return false;
#endif /* def _POSIX_VERSION or def __WIN32__ */
}
const bool classSysSetRoot(bool root) {
	if(classSysHasRoot() == root) {
		return root;
	}
#ifdef _POSIX_VERSION
	if(root) {
		if(-1 == seteuid(0)) {
			SUSUWU_PRINT(WARNING, "classSysSetRoot(true) {(-1 == seteuid(0)) /* stuck as user, perhaps is not setuid executable */}");
		}
#if 0
# ifdef __APPLE__ //TODO: https://stackoverflow.com/questions/2483755/how-to-programmatically-gain-root-privileges/35316538#35316538 says you must execute new processes to do this
# else //TODO: https://stackoverflow.com/questions/34723861/calling-a-c-function-with-root-privileges-without-executing-the-whole-program/70149223#70149223 https://stackoverflow.com/questions/70615937/how-to-run-a-command-as-root-with-c-or-c-with-no-pam-in-linux-with-password-au https://stackoverflow.com/questions/2483755/how-to-programmatically-gain-root-privileges/2483789#2483789 says you must spawn new processes to do this
		/* TODO: polkit? Until this is finished, you must use chmod (to give setuid to executable), or execute new processes (with `sudo`/`su`) if you wish to use firewall/antivirus (which require root) */
# endif /* __APPLE__ else */
#endif /* 0 */
	} else {
# if 0 && defined LINUX // TODO: pam_loginuid.so(8) // https://stackoverflow.com/questions/10272784/how-do-i-get-the-users-real-uid-if-the-program-is-run-with-sudo/10272881#10272881
		uid_t sudo_uid = audit_getloginuid();
# else /* !def linux */
		uid_t sudo_uid = getuid();
		if(0 == sudo_uid) {
			char *sudo_uid_str = getenv("SUDO_UID"), *sudo_uid_str_it;
			if(NULL == sudo_uid_str) {
				SUSUWU_PRINT(WARNING, "classSysSetRoot(false) {(NULL == getenv(\"SUDO_UID\")) /* stuck as root */}");
				return true;
			} else {
				sudo_uid = (uid_t)strtol(sudo_uid_str, &sudo_uid_str_it, 10);
				if(sudo_uid_str == sudo_uid_str_it || -1 == setuid(sudo_uid)) { /* prevent reescalation to root */
					SUSUWU_PRINT(WARNING, "classSysSetRoot(false) {(-1 == setuid(sudo_uid)) /* can't prevent reescalation to root */}");
				}
			}
		}
# endif /* !def LINUX */
		if(0 == sudo_uid) {
			SUSUWU_PRINT(WARNING, "classSysSetRoot(false) {(0 == sudo_uid) /* stuck as root */}");
		} else if(-1 == seteuid(sudo_uid)) {
			SUSUWU_PRINT(WARNING, "classSysSetRoot(false) {(-1 == seteuid(sudo_uid)) /* stuck as root */}");
		}
	}
/* #elif defined __WIN32__ */ //TODO: https://stackoverflow.com/questions/6418791/requesting-administrator-privileges-at-run-time says you must spawn new processes to do this
#else
	SUSUWU_PRINT(WARNING, "classSysSetRoot(bool) {#ifndef _POSIX_VERSION /* TODO */}");
#endif /* _POSIX_VERSION */
	return classSysHasRoot();
}

const bool classSysSetConsoleInput(bool input) {
	input ? std::cin.clear(std::ios::goodbit) : std::cin.setstate(std::ios::eofbit);
	return classSysGetConsoleInput();
}

const bool classSysTests() {
	bool retval = true;
	std::cout << "	execves(): " << std::flush;
	(EXIT_SUCCESS == execves({"/bin/echo", "pass"})) || (retval = false) || (std::cout << "error" << std::endl);
	std::cout << "	execvex(): " << std::flush;
	(EXIT_SUCCESS == execvex("/bin/echo pass")) || (retval = false) || (std::cout << "error" << std::endl);
	return retval;
}

}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassSys_cxx */

