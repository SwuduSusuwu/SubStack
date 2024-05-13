If your project can not include `C++` libraries,
please use `cfront` [ https://wikipedia.org/wiki/Cfront https://github.com/farisawan-2000/cfront-3 ] or `LLVM-Julia` (FLOSS) [ https://github.com/JuliaHubOSS/llvm-cbe ] to cross-compile this to `C` to allow reuses.
Cfront may fail to cross-compile some C++-specific features (such as exceptions,) so suggest to use `LLVM-Julia`.
Stock `LLVM` removed the `C-backend` [ https://stackoverflow.com/questions/31960290/using-the-llvm-linker-to-produce-c-code ], so must install `JuliaHubOSS` to do this.
`Comeau C/C++` [ https://wikipedia.org/wiki/Comeau_C/C++ ] is the new `cfront` (but is not FLOSS.)

Chose to use `C++` because:
`C++`'s "syntactic sugar" reduces code sizes (due to classes, templates, and the `STL`),
plus, this abstract syntax allows more room for compilers to optimize sources [ https://swudususuwu.substack.com/p/howto-run-devices-phones-laptops ]

Most languages allow you to include&use `C++` functions,
but if yours does not, and `LLVM-Julia` is not good enough for you,
please respond to this issue as to how a `C` version would assist you (could switch if enough ask for this):
https://github.com/SwuduSusuwu/SubStack/issues/3
