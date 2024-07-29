/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#pragma once
#ifndef INCLUDES_cxx_ClassSys_hxx
#define INCLUDES_cxx_ClassSys_hxx
#include <string> /* std::string */
#ifdef _POSIX_VERSION
#include <sys/types.h> /* pid_t */
#else
typedef int pid_t;
#endif
#include <vector> /* std::vector */
/* Abstractions; exec* (bash/sh), sockets (TODO), filesystems (TODO) */
namespace Susuwu {
/* `argv = argvS + NULL; envp = envpS + NULL: pid_t pid = fork() || (envpS.empty() ? execv(argv[0], &argv[0]) : execve(argv[0], &argv[0], &envp[0])); return pid;`
 * @pre @code (-1 != access(argv[0], X_OK) @endcode */
const pid_t execvesFork(/* const std::string &pathname, -- `execve` requires `&pathname == &argv[0]` */ const std::vector<const std::string> &argvS = {}, const std::vector<const std::string> &envpS = {});
static const pid_t execvexFork(const std::string &toSh) {return execvesFork({"/bin/sh", "-c", toSh});}
/* `pid_t pid = execvesFork(argvS, envpS); int status; waitpid(pid, &status, 0); return status;}` */
const int execves(const std::vector<const std::string> &argvS = {}, const std::vector<const std::string> &envpS = {});
static const int execvex(const std::string &toSh) {return execves({"/bin/sh", "-c", toSh});}
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_ClassSys_hxx */

