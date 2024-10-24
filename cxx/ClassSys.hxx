/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#pragma once
#ifndef INCLUDES_cxx_ClassSys_hxx
#define INCLUDES_cxx_ClassSys_hxx
#include "Macros.hxx" /* ERROR NOEXCEPT SUSUWU_PRINT */
#include <chrono> /* std::chrono */
#include <exception> /* std::exception */
#include <iomanip> /* std::dec std::hex */
#include <iostream> /* std::cerr std::cin std::endl */
#include <sstream> /* std::stringstream */
#include <string> /* std::string std::to_string */
#ifdef _POSIX_VERSION
#include <sys/types.h> /* pid_t */
#else
typedef int pid_t;
#endif
#include <vector> /* std::vector */
/* Abstractions to do with: `sh` scripts (such as: exec*, sudo), sockets (TODO), filesystems (TODO) */
namespace Susuwu {
extern int classSysArgc;
extern const char **classSysArgs;
/* Called from main(), stores {argc, args} into {classSysArgc, classSysArgs}
 * Much simpler to use path from args[0] (versus https://stackoverflow.com/questions/1528298/get-path-of-executable/34109000#34109000)
 * @pre @code (0 < argc && nullptr != args && nullptr != args[0]
 * @post @code (0 < classSysArgc && nullptr != classSysArgs && nullptr != classSysArgs[0] */
const bool classSysInit(int argc, const char **args);

inline const auto classSysUSecondClock() {
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
typedef decltype(classSysUSecondClock()) ClassSysUSeconds;

/* `argv = argvS + NULL; envp = envpS + NULL: pid_t pid = fork() || (envpS.empty() ? execv(argv[0], &argv[0]) : execve(argv[0], &argv[0], &envp[0])); return pid;`
 * @throw std::runtime_error("execvesFork(): {-1 == pid}, errno=" + std::to_string(errno))
 * @pre @code (-1 != access(argv[0], X_OK) @endcode */
const pid_t execvesFork(/* const std::string &pathname, -- `execve` requires `&pathname == &argv[0]` */ const std::vector<std::string> &argvS = {}, const std::vector<std::string> &envpS = {});
static const pid_t execvexFork(const std::string &toSh) {return execvesFork({"/bin/sh", "-c", toSh});}
/* `pid_t pid = execvesFork(argvS, envpS); int status; waitpid(pid, &status, 0); return status;}` */
const int execves(const std::vector<std::string> &argvS = {}, const std::vector<std::string> &envpS = {});
static const int execvex(const std::string &toSh) {return execves({"/bin/sh", "-c", toSh});}

/* #if _POSIX_VERSION, `return (0 == geteuid());` #elif __WIN32__ `return IsUserAnAdmin();` #endif `return false;` */
const bool classSysHasRoot();
/* #if _POSIX_VERSION, `root ? (seteuid(0) : (seteuid(getuid() || getenv("SUDO_UID")), setuid(geteuid)); return classSysHasRoot();` #endif
 * Usage: classSysSetRoot(true); functionsWhichRequireRoot; classSysSetRoot(false); */
const bool classSysSetRoot(bool root); /* root ? (seteuid(0) : (seteuid(getuid() || atoi(getenv("SUDO_UID"))), setuid(geteuid)); return classSysHasRoot(); */

static const bool classSysGetConsoleInput() { return std::cin.good() && !std::cin.eof(); }
const bool classSysSetConsoleInput(bool input); /* Set to `false` for unit tests/background tasks (acts as if user pressed `<ctrl>+d`, thus input prompts will use default choices.) Returns `classSysGetConsoleInput();` */

template<class Os, class Str>
inline Os &classSysHexOs(Os &os, const Str &value) {
	os << std::hex;
	for(const char ch : value) {
		os << static_cast<int>(ch);
	}
	os << std::dec;
	return os;
}
template<class Str>
inline Str classSysHexStr(const Str &value) {
	std::stringstream os;
	classSysHexOs(os, value);
	return os.str();
}

template<typename Func, typename... Args>
auto templateCatchAll(Func func, const std::string &funcName, Args... args) {
	try {
		return func(args...);
	} catch (const std::exception &ex) {
		SUSUWU_PRINT(ERROR, funcName + " {throw std::exception(\"" + ex.what() + "\");}");
		return decltype(func(args...))(); /* `func(args...)`'s default return value; if `int func(args...)`, `return 0;`. If `bool func(args...)`, `return false;` */
	}
}

/* @throw std::runtime_error */
const bool classSysTests();
static const bool classSysTestsNoexcept() NOEXCEPT {return templateCatchAll(classSysTests, "classSysTests()");}

}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassSys_hxx */

