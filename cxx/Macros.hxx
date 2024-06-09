/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDE_GUARD_cxx_Macros_hxx
#define INCLUDE_GUARD_cxx_Macros_hxx
/* Miscellaneous macros */
#include <assert.h> /* assert static_assert */
#include <stdbool.h> /* false */
#include <version> /* __cpp_lib_unreachable */ /* [https://en.cppreference.com/w/cpp/feature_test] */
namespace Susuwu { /* namespaces do not affect macros. Is just standard practice to wrap all of a project's contents with namespaces. */
#define GLUE(S, U) S##U /* concatanates 2 constants */

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

#ifdef USE_CONTRACTS /* Pass `-D USE_CONTRACTS` once compiler has C++26 (Contracts) */
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
#elif (!defined USE_ASSUME) || USE_ASSUME /* Default: if(!NDEBUG) USE_ASSUME=true; pass `-D USE_ASSUME=false` to disable this */ 
/* Release: Promises `(true == (X))`, for compiler which optimizes this. Warning: `if(!(X)) {UB (undefined behaviour)}` */
#	ifdef IS_MSVC
#		define ASSUME(X) __assume(X)
#	elif __clang__ /* `~ $ clang++` */
#		define ASSUME(X) __builtin_assume(X)
#	else /* (!def IS_MSVC) && (!def __clang__) */
#		define ASSUME(X) (static_cast<void>(X) || UNREACHABLE)
#	endif /* !def IS_MSVC */
#else /* !def USE_ASSUME */
#	define ASSUME(X)
#endif /* !def USE_ASSUME */

#if defined(__clang__) && __has_feature(cxx_noexcept) || defined(__GXX_EXPERIMENTAL_CXX0X__) && __GNUC__ * 10 + __GNUC_MINOR__ >= 46 || defined(_MSC_FULL_VER) && _MSC_FULL_VER >= 180021114 /* [Other `noexcept` tests](https://stackoverflow.com/questions/18387640/how-to-deal-with-noexcept-in-visual-studio) */
#	define NOEXCEPT noexcept /* Usage: `void versionInfo() NOEXCEPT;` is close to `void versionInfo() [[ensures: true]];` or `versionInfo(); !UNREACHABLE;*/
#endif /* supports noexcept */
#if (defined __has_cpp_attribute) && __has_cpp_attribute(noreturn) /* TODO: [Cmake test for `\[\[noreturn\]\]`](https://stackoverflow.com/a/33517293/24473928) */
#	define NORETURN [[noreturn]] /* Usage: `NORETURN void exit();` is close to `void exit() [[ensures:: false]];` or `exit(); UNREACHABLE;*/
#endif /* supports [[noreturn]] */
}; /* namespace Susuwu */
#endif /* ndef INCLUDE_GUARD_cxx_Macros_hxx */

