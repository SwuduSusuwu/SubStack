/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#pragma once
#ifndef INCLUDES_cxx_Sys_hxx
#define INCLUDES_cxx_Sys_hxx
#include <string> /* std::string */
#include <vector> /* std::vector */
/* Abstractions; exec* (bash/sh), sockets (TODO), filesystems (TODO) */
namespace Susuwu {
/* `argv = argvS + NULL; envp = envpS + NULL: pid_t pid = fork() || (envpS.empty() ? execv(argv[0], &argv[0]) : execve(argv[0], &argv[0], &envp[0])); int status; waitpid(pid, &status, 0); return status;`
 * @pre @code (-1 != access(argv[0], X_OK) @endcode */
const int execves(/* const std::string &pathname, -- `execve` requires `&pathname == &argv[0]` */ const std::vector<const std::string> &argvS = {}, const std::vector<const std::string> &envpS = {});
static const int execvex(const std::string &toSh) {return execves({"/bin/sh", "-c", toSh});}
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_Sys_hxx */

