#!/bin/sh
echo '# /* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */'
#cd build
sSRC="./cxx/"
#INCLUDES="${sSRC}"
#export CXX_FLAGS="-I${INCLUDES}"
CXX_FLAGS_RELEASE="-fomit-frame-pointer -DNDEBUG -O2"
CXX_FLAGS_DEBUG="-fsanitize=address -fno-sanitize-recover=all -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow -fno-sanitize=null -fno-sanitize=alignment" #/* supports `g++`/`clang++`: https://developers.redhat.com/blog/2021/05/05/memory-error-checking-in-c-and-c-comparing-sanitizers-and-valgrind#tldr */
CXX_FLAGS_DEBUG="${CXX_FLAGS_DEBUG} -fno-omit-frame-pointer" #/* thus optimization won't remove stacktraces: https://stackoverflow.com/questions/48234575/g-will-fno-omit-frame-pointer-be-effective-if-specified-before-o2-or-o3 https://clang.llvm.org/docs/MemorySanitizer.html */
CXX_FLAGS_DEBUG="${CXX_FLAGS_DEBUG} -g" #/* extra symbols (line numbers + arguments) to stacktraces */
#CXX_FLAGS_DEBUG="${CXX_FLAGS_DEBUG} -fno-optimize-sibling-calls" #/* Don't inline functions. Does extra stacktraces. */
#CXX_FLAGS_DEBUG="${CXX_FLAGS_DEBUG} -fsanitize=undefined" #/* causes 'cannot locate symbol "__ubsan_handle_function_type_mismatch_abort"' */
if command -v ctags > /dev/null; then
	ctags -R
fi
if command -v clang++ > /dev/null; then
	CXX="clang++"
elif command -v g++ > /dev/mull; then
	CXX="g++"
else
	echo "Error: no clang++, no g++. `apt install clang` or `apt install gcc`"
	exit 1
fi
if [ "--release" = "$1" ]; then
	echo "# /* \`$0 --release\` does not support profilers/debuggers (use \`$0 --debug\` for this) */"
	CXX_FLAGS="${CXX_FLAGS} ${CXX_FLAGS_RELEASE}"
else
	echo "# /* \`$0\` defaults to \`$0 --debug\`. Use \`$0 --release\` if you want fast executables */"
	CXX_FLAGS="${CXX_FLAGS} ${CXX_FLAGS_DEBUG}"
	export ASAN_OPTIONS=abort_on_error=1:fast_unwind_on_malloc=0:detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 #/* "For LLDB/GDB and to prevent very short stack traces and usually false leaks detection" */
fi
CXX="${CXX} ${CXX_FLAGS}"
rm *.o
set -x
$CXX -x c -c ${sSRC}/../c/rfc6234/sha1.c
$CXX -x c -c ${sSRC}/../c/rfc6234/sha224-256.c
$CXX -x c -c ${sSRC}/../c/rfc6234/sha384-512.c
$CXX -c ${sSRC}/ClassSha2.cxx
$CXX -c ${sSRC}/ClassResultList.cxx
$CXX -c ${sSRC}/ClassCns.cxx
$CXX -c ${sSRC}/VirusAnalysis.cxx
$CXX -c ${sSRC}/ConversationCns.cxx
$CXX -c ${sSRC}/main.cxx
$CXX sha1.o sha224-256.o sha384-512.o ClassSha2.o ClassResultList.o ClassCns.o VirusAnalysis.o ConversationCns.o main.o
set +x

