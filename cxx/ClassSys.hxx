/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#pragma once
#ifndef INCLUDES_cxx_ClassSys_hxx
#define INCLUDES_cxx_ClassSys_hxx
#include <exception> /* std::exception */
#include <iostream> /* std::cerr std::endl */
#include <string> /* std::string */
#ifdef _POSIX_VERSION
#include <sys/types.h> /* pid_t */
#else
typedef int pid_t;
#endif
#include <vector> /* std::vector */
/* Abstractions to do with: `sh` scripts (such as: exec*, sudo), sockets (TODO), filesystems (TODO) */
namespace Susuwu {
/* `argv = argvS + NULL; envp = envpS + NULL: pid_t pid = fork() || (envpS.empty() ? execv(argv[0], &argv[0]) : execve(argv[0], &argv[0], &envp[0])); return pid;`
 * @pre @code (-1 != access(argv[0], X_OK) @endcode */
const pid_t execvesFork(/* const std::string &pathname, -- `execve` requires `&pathname == &argv[0]` */ const std::vector<const std::string> &argvS = {}, const std::vector<const std::string> &envpS = {});
static const pid_t execvexFork(const std::string &toSh) {return execvesFork({"/bin/sh", "-c", toSh});}
/* `pid_t pid = execvesFork(argvS, envpS); int status; waitpid(pid, &status, 0); return status;}` */
const int execves(const std::vector<const std::string> &argvS = {}, const std::vector<const std::string> &envpS = {});
static const int execvex(const std::string &toSh) {return execves({"/bin/sh", "-c", toSh});}

/* #if _POSIX_VERSION, `return (0 == geteuid());` #elif __WIN32__ `return IsUserAnAdmin();` #endif `return false;` */
const bool hasRoot();
/* #if _POSIX_VERSION, `root ? (seteuid(0) : (seteuid(getuid() || getenv("SUDO_UID")), setuid(geteuid)); return hasRoot();` #endif
 * Usage: setRoot(true); functionsWhichRequireRoot; setRoot(false); */
const bool setRoot(bool root); /* root ? (seteuid(0) : (seteuid(getuid() || atoi(getenv("SUDO_UID"))), setuid(geteuid)); return hasRoot(); */

template<typename Func, typename... Args>
auto templateCatchAll(Func func, Args... args) {
	try {
		return func(args...);
	} catch (const std::exception &ex) {
		std::cerr << "[Error: {throw std::exception(\"" << ex.what() << "\");}]" << std::endl;
		return decltype(func(args...))(); /* `func(args...)`'s default return value; if `int func(args...)`, `return 0;`. If `bool func()`, `return false;` */
	}
}
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassSys_hxx */

