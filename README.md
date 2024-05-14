Licenses: dual `Creative Commons`/`Apache 2,0` (allows all uses)

Purposes: `/posts/` stages posts (school classes) for https://SwuduSusuwu.substack.com/

Purposes: `/cxx/` C++ implementations ( based off of ideas/pseudocodes from https://SwuduSusuwu.substack.com/ , most of which is about autonomous tools, or artificial central nervous systems)

Targets: Windows/Linux/Android/OSX/iOS; all C++ compilers, requires some extensions (such as `for(auto x : s) {}`)

Todo: `. make.sh` success. Is work-in-progress.

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

