#!/bin/sh
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
$GXX -c ${sSRC}/ClassResultList.cxx
$GXX -c ${sSRC}/ClassCns.cxx
$GXX -c ${sSRC}/VirusAnalysis.cxx
$GXX -c ${sSRC}/ConversationCns.cxx

