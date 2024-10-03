Dual licenses: choose `Creative Commons` or `Apache 2` (allows all uses).

Purposes: `/posts/` stages posts (school classes) for https://SwuduSusuwu.substack.com/

Purposes: `/cxx/` C++ implementations ( based off of ideas/pseudocodes from https://SwuduSusuwu.substack.com/ , most of which is about autonomous tools, or artificial central nervous systems)

Targets: Windows/Linux/Android/OSX/iOS; all C++ compilers, requires some extensions (such as `for(auto x : s) {}`)

Usage: `./build.sh` produces `*.o` static libraries (for distribution to others,) plus `a.out` to do unit tests (test harnesses).

Conventions = Mozilla Org (ergo Firefox) style:

    Files: #import "PascalCase.hxx"

    Structs, enums, classe: typedef struct PascalCase {} PascalCase; typedef enum PascalCase {} PascalCase; typedef class PascalCase {} PascalCase;

    Macros: #define CONSTANT_CASE(snake_case) assert("Normal");

    Indentation = tabs; as much tabs as braces

    Braces, functions:

        bool camelCase(bool s, bool x) {

            if(s && x) {

        return s;

            } else {

            return x;

            }

        }

    Variables, objects: const bool `camelCase = true`; Global variables/objects: `extern classPrefixCamelCase;`

    `git add NewFile`: "+NewFile", `git rm Exists`: "-Exists", `touch Exists && git add Exists`: "@Exists"

    Simple wildcards/regex for multiple files: "@ChangedPath/.* -> NewPath/.*" or `%s/oldFunction/newFunction/`

    Include guards:

        #ifndef INCLUDES_Path_To_File

        #define INCLUDES_Path_To_File

        #endif /* ndef INCLUDES_Path_To_File */

Conventions +=
    [Indent multi-level macros as `#if X # if S ,,, # endif #endif`](https://stackoverflow.com/questions/1854550/c-macro-define-indentation)
    [\_DEBUG is specific to MSVC, thus use NDEBUG](https://stackoverflow.com/questions/2290509/debug-vs-ndebug), [Pass `-D NDEBUG` to disable asssets + enable optimizations](https://stackoverflow.com/questions/2249282/c-c-portable-way-to-detect-debug-release)
    Do not perform tasks within `assert()`, due to: the standard says "[`#if NDEBUG\n#define assert(x) (0)\n#endif`]".
    All userland errors should go to `throw std::exception()` _or derivatives of std::exception_, `std::cerr`, `extern int errno;`, or `return errno;`. Comments about possible errors should go above function declarations (Doxygen convention).
        `throw` / `std:cerr` should use the new common syntax for this: `"[WARN_LEVEL: OPTIONAL_FUNCTION_NAME {code which triggered the error/warning/diagnostic/notice} /* OPTIONAL COMMENTS */]"`, 
        cxx/Macros.hxx:{SUSUWU_STR(x), SUSUWU_CERR(x), SUSUWU_STDOUT(x)} have the new syntax for this
    [Doxygen-ish "@pre"/"@post" prepares for C++26 Contracts](https://github.com/doxygen/doxygen/issues/6702): 
```
        /* @throw std::bad_alloc If function uses {malloc, realloc, new[], std::*::{push_back, push_front, insert}}
         * @throw std::logic_error Optional. Would include most functions which use std::*
         * @pre @code !output.full() @endcode
         * @post @code !output.empty() @endcode
         */
        bool functionDeclaration(std::string input, std::deque<vector> output);
```
        It is arguable whether or not you should document such possible system errors; almost all Standard Template Library functions can throw derivatives of `std::logic_error`.
        Regex `:%s/@pre (.*) @code (.*) @endcode/[[expects: \2]] \\* \1 \\*/` `:%s/@post (.*) @code (.*) @endcode/[[ensures: \2]] \\* \1 \\*/` once have Contracts/C++26
        cxx/Macros.cxx has `ASSUME(X)`, which is close to `[[expects: x]]`, but `ASSUME(X)` goes to `*.cxx`, whereas `[[expects]]` goes to `*.hxx`.
        Documentation of interfaces belongs to `*.hxx`; `*.cxx` is to do implementations. Do not duplicate interface comments.
        Advantages of `[[expects]]`; allows to move information of interfaces out of `*.cxx`, to `*.hxx`.

