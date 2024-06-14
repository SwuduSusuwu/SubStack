#!/bin/sh
echo '/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */'
#cd build
sSRC="./cxx/"
#INCLUDES="${sSRC}"
#export CXX_FLAGS="-I${INCLUDES}"
if command -v ctags; then
	ctags -R
fi
if command -v clang++; then
	GXX="clang++"
elif command -v g++; then
	GXX="g++"
else
	echo "Error: no clang++, no g++. `apt install clang` or `apt install gcc`"
	exit 1
fi
rm *.o
$GXX -x c -c ${sSRC}/../c/rfc6234/sha1.c
$GXX -x c -c ${sSRC}/../c/rfc6234/sha224-256.c
$GXX -x c -c ${sSRC}/../c/rfc6234/sha384-512.c
$GXX -c ${sSRC}/ClassSha2.cxx
$GXX -c ${sSRC}/ClassResultList.cxx
$GXX -c ${sSRC}/ClassCns.cxx
$GXX -c ${sSRC}/VirusAnalysis.cxx
$GXX -c ${sSRC}/ConversationCns.cxx
$GXX -c ${sSRC}/main.cxx
$GXX sha1.o sha224-256.o sha384-512.o ClassSha2.o ClassResultList.o ClassCns.o VirusAnalysis.o ConversationCns.o main.o

