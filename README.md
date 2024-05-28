Licenses: dual `Creative Commons`/`Apache 2,0` (allows all uses)

Purposes: `/posts/` stages posts (school classes) for https://SwuduSusuwu.substack.com/

Purposes: `/cxx/` C++ implementations ( based off of ideas/pseudocodes from https://SwuduSusuwu.substack.com/ , most of which is about autonomous tools, or artificial central nervous systems)

Targets: Windows/Linux/Android/OSX/iOS; all C++ compilers, requires some extensions (such as `for(auto x : s) {}`)

Todo: `. make.sh` is success, but just produces static libraries (for distribution to others.) Should produce executables (demos) + do unit tests (integration of test harnesses).

Conventions = Mozilla Org (ergo Firefox) style:

    Files: #import "PascalCase.hxx"

    Structs, enums, classe: typedef struct PascalCase {} PascalCase; typedef enum PascalCase {} PascalCase; typedef class PascalCase {} PascalCase;

    Macros: #define CONSTANT_CASE(snake_case) assert("Normal");

    Indentation = tabs; as much tabs as braces

    Braces:

        bool F(bool s, bool x) {

            if(s && x) {

        return s;

            } else {

            return x;

            }

        }

    Variables, objects: const bool camelCase = true;

    `git add NewFile`: "+NewFile", `git rm Exists`: "-Exists", `touch Exists && git add Exists`: "@Exists"

    Simple wildcards/regex for multiple files: "@ChangedPath/.* -> NewPath/.*"

    Include guards:

        #ifndef INCLUDES_Path_To_File

        #define INCLUDES_Path_To_File

        #endif /* ndef INCLUDES_Path_To_File */

Conventions +=
    [\_DEBUG is specific to MSVC, thus use NDEBUG](https://stackoverflow.com/questions/2290509/debug-vs-ndebug), [Pass `-D NDEBUG` to disable asssets + enable optimizations](https://stackoverflow.com/questions/2249282/c-c-portable-way-to-detect-debug-release)
    All userland errors should go to `throw()`, or a global `int errno;` variable, or `return errno;`, with comments above declarations of such functions.
    [Doxygen-ish "@pre"/"@post" prepares for C++26 Contracts](https://github.com/doxygen/doxygen/issues/6702): 
```
        /* @throw std::bad_alloc If function uses {malloc, realloc, new[], std::*::{push_back, push_front, insert}}
         * @throw std::logic_error Optional. Would include most functions which use std::*
         * @pre @code !output.full() @endcode
         * @post @code output.size() @endcode
         */
        bool functionDeclaration(std::string input, std::deque<vector> output);
```
        It is arguable whether or not you should document such possible system errors; almost all Standard Template Library functions can throw derivatives of `std::logic_error`.
        Regex `:%s/@pre (.*) @code (.*) @endcode/[[expects: \2]] \\* \1 \\*/` `:%s/@post (.*) @code (.*) @endcode/[[ensures: \2]] \\* \1 \\*/` once have Contracts/C++26
        cxx/Macros.cxx has `ASSUME(X)`, which is close to `[[expects: x]]`, but `ASSUME(X)` goes to `*.cxx`, whereas `[[expects]]` goes to `*.hxx`.
        Documentation of interfaces belongs to `*.hxx`; `*.cxx` is to do implementations. Do not duplicate interface comments.
        Advantages of `[[expects]]`; allows to move information of interfaces out of `*.cxx`, to `*.hxx`.

