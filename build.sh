#!/bin/sh
echo '[Notice: Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses)]'
#cd build
sSRC="./cxx/"
#INCLUDES="${sSRC}"
#export CXX_FLAGS="-I${INCLUDES}"
CXX_FLAGS_ANALYSIS="-Wall -Wno-unused -Wno-unused-function -Wextra -Wno-unused-parameter -Wno-ignored-qualifiers" #TODO: `-Werror` without `-Wno-*`
CXX_FLAGS_RELEASE="${CXX_FLAGS_ANALYSIS} -fomit-frame-pointer -DNDEBUG -O2"
CXX_FLAGS_DEBUG="${CXX_FLAGS_ANALYSIS} -fsanitize=address -fno-sanitize-recover=all -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow -fno-sanitize=null -fno-sanitize=alignment" #/* supports `g++`/`clang++`: https://developers.redhat.com/blog/2021/05/05/memory-error-checking-in-c-and-c-comparing-sanitizers-and-valgrind#tldr */
CXX_FLAGS_DEBUG="${CXX_FLAGS_DEBUG} -fno-omit-frame-pointer" #/* thus optimization won't remove stacktraces: https://stackoverflow.com/questions/48234575/g-will-fno-omit-frame-pointer-be-effective-if-specified-before-o2-or-o3 https://clang.llvm.org/docs/MemorySanitizer.html */
CXX_FLAGS_DEBUG="${CXX_FLAGS_DEBUG} -g" #/* extra symbols (line numbers + arguments) to stacktraces */
#CXX_FLAGS_DEBUG="${CXX_FLAGS_DEBUG} -fno-optimize-sibling-calls" #/* Don't inline functions. Does extra stacktraces. */
#CXX_FLAGS_DEBUG="${CXX_FLAGS_DEBUG} -fsanitize=undefined" #/* causes 'cannot locate symbol "__ubsan_handle_function_type_mismatch_abort"' */
if command -v ctags > /dev/null; then
	ctags -R
fi
CROSS_COMP=""
if [ "--mingw" = "$1" ] || [ "--mingw" = "$2" ]; then
	CROSS_COMP=" --mingw"
	if command -v x86_64-w64-mingw32-clang++ > /dev/null; then
		CXX="x86_64-w64-mingw32-clang++"
	elif command -v x86_64-w64-mingw32-g++ > /dev/null; then
		CXX="x86_64-w64-mingw32-g++"
	else
		echo "[Error: \`x86_64-w64-mingw32-clang++ not found\`, \`x86_64-w64-mingw32-g++ not found\`. Do \`apt install llvm-mingw-w64\` or \`apt install mingw-w64\`]"
		exit 1
	fi
elif command -v clang++ > /dev/null; then
	CXX="clang++"
elif command -v g++ > /dev/mull; then
	CXX="g++"
else
	echo "[Error: \`clang++ not found\`, \`g++ not found\`. Do \`apt install clang\` or \`apt install gcc\`]"
	exit 1
fi
if [ "--release" = "$1" ] || [ "--release" = "$2" ]; then
	echo "[Notice: \`${0}${CROSS_COMP} --release\` does not support profilers/debuggers (use \`$0${CROSS_COMP} --debug\` for this)]"
	CXX_FLAGS="${CXX_FLAGS} ${CXX_FLAGS_RELEASE}"
else
	if [ "--debug" != "$1" ] && [ "--debug" != "$2" ]; then
		echo -n "[Notice: \`${0}${CROSS_COMP}\` defaults to \`${0}${CROSS_COMP} --debug\`.] "
	fi
	echo "[Notice: Use \`${0}${CROSS_COMP} --release\` to improve how fast this executes]"
	CXX_FLAGS="${CXX_FLAGS} ${CXX_FLAGS_DEBUG}"
	export ASAN_OPTIONS=abort_on_error=1:fast_unwind_on_malloc=0:detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 #/* "For LLDB/GDB and to prevent very short stack traces and usually false leaks detection" */
fi
CXX="${CXX} ${CXX_FLAGS}"
set -x
$CXX -x c -c ${sSRC}/../c/rfc6234/sha1.c
$CXX -x c -c ${sSRC}/../c/rfc6234/sha224-256.c
$CXX -x c -c ${sSRC}/../c/rfc6234/sha384-512.c
$CXX -c ${sSRC}/ClassSha2.cxx
$CXX -c ${sSRC}/ClassResultList.cxx
$CXX -c ${sSRC}/ClassSys.cxx
$CXX -c ${sSRC}/ClassCns.cxx
$CXX -c ${sSRC}/VirusAnalysis.cxx
$CXX -c ${sSRC}/AssistantCns.cxx
$CXX -c ${sSRC}/main.cxx
$CXX sha1.o sha224-256.o sha384-512.o ClassSha2.o ClassResultList.o ClassSys.o ClassCns.o VirusAnalysis.o AssistantCns.o main.o
STATUS=$?
set +x
return $STATUS

