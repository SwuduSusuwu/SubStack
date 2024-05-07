#!/bin/sh
#cd build
sSRC="./c++/"
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
$GXX -c ${sSRC}/ClassResultList.c++ 
$GXX -c ${sSRC}/ClassCns.c++ 
$GXX -c ${sSRC}/VirusAnalysis.c++ 
$GXX -c ${sSRC}/ConversationCns.c++ 

