/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDES_cxx_Macros_hxx
#define INCLUDES_cxx_Macros_hxx
/* Miscellaneous macros */
#include <string> /* std::cerr std::endl */
#include <cassert> /* assert static_assert */
#include <cstdbool> /* false */
#include <version> /* __cpp_lib_unreachable */ /* [https://en.cppreference.com/w/cpp/feature_test] */
namespace Susuwu { /* namespaces do not affect macros. Is just standard practice to wrap all of a project's contents with namespaces. */
/* To printout default preprocessor definitions:
 * for X={clang, clang++, gcc, g++, hipcc, icc}: `$X -dM -E -x c++ /dev/null`
 * replace `/dev/null` with a file (such as `cxx/Macros.hxx`) to printout actual preprocessor definitions
 * for MSVC: `git clone --depth 1 https://github.com/MicrosoftDocs/cpp-docs.git && vim cpp-docs/blob/main/docs/preprocessor/predefined-macros.md` or browse to https://learn.microsoft.com/en-us/cpp/preprocessor/predefined-macros 
 * for others: `git clone https://github.com/cpredef/predef.git && vim predef/Compilers.md`
 */ /* To pass new preprocessor definitions (example is `#define USE_CONTRACTS true`):
 * to `clang`/`clang++`/`gcc`/`g++`/Intel(`icc`): `-DUSE_CONTRACTS=true`
 * to MSVC(`cl`): `\DUSE_CONTRACTS=true`
 */
#define SUSUWU_GLUE2(S, U) S##U /* concatanates 2 macro constants */
#define SUSUWU_GLUE(S, U) SUSUWU_GLUE2(S, U) /* concatanates 2 macro functions or constants */

#if SKIP_CONSOLE_COLORS /* `g++ -DSKIP_CONSOLE_COLORS=1` to turn colors off */
# define SUSUWU_SH_DEFAULT ""
# define SUSUWU_SH_BLACK ""
# define SUSUWU_SH_DARK_GRAY ""
# define SUSUWU_SH_RED ""
# define SUSUWU_SH_LIGHT_RED ""
# define SUSUWU_SH_GREEN ""
# define SUSUWU_SH_LIGHT_GREEN ""
# define SUSUWU_SH_BROWN ""
# define SUSUWU_SH_YELLOW ""
# define SUSUWU_SH_BLUE ""
# define SUSUWU_SH_LIGHT_BLUE ""
# define SUSUWU_SH_PURPLE ""
# define SUSUWU_SH_LIGHT_PURPLE ""
# define SUSUWU_SH_CYAN ""
# define SUSUWU_SH_LIGHT_CYAN ""
# define SUSUWU_SH_LIGHT_GRAY ""
# define SUSUWU_SH_WHITE ""
#else /* !SKIP_CONSOLE_COLORS */
# define SUSUWU_SH_DEFAULT "\033[0m"
# define SUSUWU_SH_BLACK "\033[0;30m"
# define SUSUWU_SH_DARK_GRAY "\033[1;30m"
# define SUSUWU_SH_RED "\033[0;31m"
# define SUSUWU_SH_LIGHT_RED "\033[1;31m"
# define SUSUWU_SH_GREEN "\033[0;32m"
# define SUSUWU_SH_LIGHT_GREEN "\033[1;32m"
# define SUSUWU_SH_BROWN "\033[0;33m"
# define SUSUWU_SH_YELLOW "\033[1;33m"
# define SUSUWU_SH_BLUE "\033[0;34m"
# define SUSUWU_SH_LIGHT_BLUE "\033[1;34m"
# define SUSUWU_SH_PURPLE "\033[0;35m"
# define SUSUWU_SH_LIGHT_PURPLE "\033[1;35m"
# define SUSUWU_SH_CYAN "\033[0;36m"
# define SUSUWU_SH_LIGHT_CYAN "\033[1;36m"
# define SUSUWU_SH_LIGHT_GRAY "\033[0;37m"
# define SUSUWU_SH_WHITE "\033[1;37m"
#endif /* !SKIP_CONSOLE_COLORS */
#define SUSUWU_SH_ERROR "[" SUSUWU_SH_RED "Error: " SUSUWU_SH_WHITE
#define SUSUWU_SH_WARNING "[" SUSUWU_SH_PURPLE "Warning: " SUSUWU_SH_WHITE
#define SUSUWU_SH_INFO "[" SUSUWU_SH_CYAN "Info: " SUSUWU_SH_WHITE
#define SUSUWU_SH_SUCCESS "[" SUSUWU_SH_GREEN "Success: " SUSUWU_SH_WHITE
#define SUSUWU_SH_NOTICE "[" SUSUWU_SH_BLUE "Notice: " SUSUWU_SH_WHITE
#define SUSUWU_SH_DEBUG "[" SUSUWU_SH_BLUE "Debug: " SUSUWU_SH_WHITE
#define SUSUWU_SH_CLOSE_ SUSUWU_SH_DEFAULT "]"

/* WARN_LEVEL = {ERROR, WARNING, INFO, SUCCESS, NOTICE, DEBUG} */
#define SUSUWU_ERRSTR(WARN_LEVEL, x) std::string(SUSUWU_GLUE2(SUSUWU_SH_, WARN_LEVEL)) + std::string(x) + std::string(SUSUWU_SH_CLOSE_)
#define SUSUWU_CERR(WARN_LEVEL, x) std::cerr << SUSUWU_GLUE2(SUSUWU_SH_, WARN_LEVEL) << x << SUSUWU_SH_CLOSE_ << std::endl
#define SUSUWU_STDERR(WARN_LEVEL, x) fprintf(stderr, SUSUWU_GLUE2(SUSUWU_SH_, WARN_LEVEL) "%s" SUSUWU_SH_CLOSE_ "\n", x)

/* Use this to do C versus C++ agnostic messages */
#ifdef __cplusplus
# define SUSUWU_PRINT(LEVEL, x) SUSUWU_CERR(LEVEL, x)
#else /* !(defined __cplusplus */
# define SUSUWU_PRINT(LEVEL, x) SUSUWU_STDERR(LEVEL, x)
#endif /* !(defined __cplusplus */
#define SUSUWU_ERROR(x) SUSUWU_PRINT(ERROR, x)
#define SUSUWU_WARNING(x) SUSUWU_PRINT(WARNING, x)
#define SUSUWU_INFO(x) SUSUWU_PRINT(INFO, x)
#define SUSUWU_SUCCESS(x) SUSUWU_PRINT(SUCESS, x)

/* Use this to limit notices/diagnostics to release builds (+ do conditional execution) */
#ifdef NDEBUG
# define SUSUWU_NOTICE(x) (true)/* skip */
# define SUSUWU_DEBUG(x) (true)/* skip */
# define SUSUWU_DEBUGEXECUTE(x) (true)/*skip*/
#else /* !(defined NDEBUG) */
# define SUSUWU_NOTICE(x) SUSUWU_PRINT(NOTICE, x)
# define SUSUWU_DEBUG(x) SUSUWU_PRINT(DEBUG, x)
# define SUSUWU_DEBUGEXECUTE(x) x
#endif /* !(defined NDEBUG) */

/* Use this to reduce (conditional) print + (unconditional) execute into single statement */
#define SUSUWU_INFO_EXECUTE(x) ((SUSUWU_INFO(#x)), (x))
#define SUSUWU_NOTICE_EXECUTE(x) ((SUSUWU_NOTICE(#x)), (x))
#define SUSUWU_DEBUG_EXECUTE(x) ((SUSUWU_DEBUG(#x)), (x))

/* Use this to reduce (conditional) print + (conditional) execute into single statement */
#define SUSUWU_INFO_DEBUGEXECUTE(x) ((SUSUWU_INFO(#x)), SUSUWU_DEBUGEXECUTE(x))
#define SUSUWU_NOTICE_DEBUGEXECUTE(x) ((SUSUWU_NOTICE(#x)), SUSUWU_DEBUGEXECUTE(x))
#define SUSUWU_DEBUG_DEBUGEXECUTE(x) ((SUSUWU_DEBUG(#x)), SUSUWU_DEBUGEXECUTE(x))

#ifndef __has_feature
#define __has_feature(X) 0 /* `gcc` "error: missing binary operator before token \"(\"" fix */
#endif /* ndef __has_feature */
#if (!defined _POSIX_VERSION) && (_POSIX_C_SOURCE)
#define _POSIX_VERSION _POSIX_C_SOURCE /* "Error: ... ndef _POSIX_VERSION" fix */
#endif /* (!defined _POSIX_VERSION) && (_POSIX_C_SOURCE) */

#if (!defined __WIN32__) && (defined _WIN32 /* || defined __CYGWIN__ should use "#ifdef _POSIX_VERSION" path */ || __MSC_VER)
# define __WIN32__ /* https://stackoverflow.com/questions/430424/are-there-any-macros-to-determine-if-my-code-is-being-compiled-to-windows/430435#430435 says that __WIN32__ is not always defined on Windows targets */
#endif

/* `UNREACHABLE` is close to `ASSUME(false)` */
#if (!defined NDEBUG) && (defined static_assert)
/* [https://stackoverflow.com/questions/2249282/c-c-portable-way-to-detect-debug-release] [https://stackoverflow.com/questions/2290509/debug-vs-ndebug] */
/* Debug: Promises unreachable, for static analysis */
#	define UNREACHABLE static_assert(false)
#elif (!defined NDEBUG)
#	define UNREACHABLE assert(false)
#elif __cpp_lib_unreachable
/* Release: Promises executable can not reach this spot, for compiler which optimizes this. Warning: `UNREACHABLE && UB (undefined behaviour)` */
#include <utility> /* std::unreachable() */
#	define UNREACHABLE std::unreachable()
#elif (defined __GNUC__) && ((4 <= __GNUC__ && 4 < __GNUC_MINOR__) || 4 < __GNUC__) /* `~ $ g++` */
#	define UNREACHABLE __builtin_unreachable()
#else /* else (!def NDEBUG) && (!supports unreachable) */
#	define UNREACHABLE /* No-op */
#endif /* __cpp_lib_unreachable elif IS_GCC ...*/

#ifdef USE_CONTRACTS /* Pass `-DUSE_CONTRACTS` once compiler has C++26 (Contracts) */
/* `EXPECTS(X)` is close to `@pre @code X @endcode` or `ASSUME(X)` but is for headers; https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2521r2.html */
/* Promises `(true == (X))`, for static analysis, or for compiler which optimizes this. Warning: `if(!(X)) {UB (undefined behaviour)}` */
#	define EXPECTS(X) [[expects: X]] /* Usage: `void pushf(std::deque<float> &x, float f) EXPECTS(!x.full());` */
#	define ENSURES(X) [[ensures: X]] /* Usage: `void pushf(std::deque<float> &x, float f) ENSURES(0 != x.size());` */
#else /* else !def USE_CONTRACTS */
#	define EXPECTS(X) /* `@pre @code X @endcode` */
#	define ENSURES(X) /* `@post @code X @encode` */
#endif /* else !def USE_CONTRACTS */

/* `ASSUME(X)` is close to `@pre @code X @endcode` or `[[expects: x]]` */
/* TODO: choose best of [various possible ASSUME macros](https://stackoverflow.com/questions/44054078/how-to-guide-gcc-optimizations-based-on-assertions-without-runtime-cost) */
#ifndef NDEBUG
/* Debug: Promises `(true == (X))`, for static analysis */
#	define ASSUME(X) assert(X)
#elif (!defined USE_ASSUME) || USE_ASSUME /* Default: if(!NDEBUG) USE_ASSUME=true; pass `-DUSE_ASSUME=false` to disable this */ 
/* Release: Promises `(true == (X))`, for compiler which optimizes this. Warning: `if(!(X)) {UB (undefined behaviour)}` */
#	ifdef IS_MSVC
#		define ASSUME(X) __assume(X)
#	elif __clang__ /* `~ $ clang++` */
#		define ASSUME(X) __builtin_assume(X)
#	else /* (!def IS_MSVC) && (!def __clang__) */
#		define ASSUME(X) ((X) ? static_cast<void>(0) : UNREACHABLE)
#	endif /* !def IS_MSVC */
#else /* !def USE_ASSUME */
#	define ASSUME(X)
#endif /* !def USE_ASSUME */

#if defined(__clang__) && __has_feature(cxx_noexcept) || defined(__GXX_EXPERIMENTAL_CXX0X__) && __GNUC__ * 10 + __GNUC_MINOR__ >= 46 || defined(_MSC_FULL_VER) && _MSC_FULL_VER >= 180021114 /* [Other `noexcept` tests](https://stackoverflow.com/questions/18387640/how-to-deal-with-noexcept-in-visual-studio) */
#	define NOEXCEPT noexcept /* Usage: `void versionInfo() NOEXCEPT;` is close to `void versionInfo() [[ensures: true]];` or `versionInfo(); !UNREACHABLE;*/
#else /* !supports noexcept */
#	define NOEXCEPT /* old `g++`/`clang++` "error: expected function body after function declarator" fix */
#endif /* !supports noexcept */
#if (defined __has_cpp_attribute) && __has_cpp_attribute(noreturn) /* TODO: [Cmake test for `\[\[noreturn\]\]`](https://stackoverflow.com/a/33517293/24473928) */
#	define NORETURN [[noreturn]] /* Usage: `NORETURN void exit();` is close to `void exit() [[ensures:: false]];` or `exit(); UNREACHABLE;*/
#else /* !supports [[noreturn]] */
#	define NORETURN /* old `g++` "error: 'NORETURN' does not name a type" / old `clang++` "error: unknown type name 'NORETURN'" fix */
#endif /* !supports [[noreturn]] */
}; /* namespace Susuwu */
#endif /* ndef INCLUDES_cxx_Macros_hxx */

