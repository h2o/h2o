@echo off

:top
shift
if "%0" equ "" goto :eof
if "%0" equ "--cflags" goto cflags
if "%0" equ "--ldflags" goto ldflags
if "%0" equ "--ldflags-before-libs" goto ldflagsbeforelibs
if "%0" equ "--libs" goto libs
if "%0" equ "--help" goto showhelp
echo Invalid Option
goto :eof

:cflags
echo MRUBY_CFLAGS
goto top

:libs
echo MRUBY_LIBS
goto top

:ldflags
echo MRUBY_LDFLAGS
goto top

:ldflagsbeforelibs
echo MRUBY_LDFLAGS_BEFORE_LIBS
goto top

:showhelp
echo Usage: mruby-config [switches]
echo   switches:
echo   --cflags                   print flags passed to compiler
echo   --ldflags                  print flags passed to linker
echo   --ldflags-before-libs      print flags passwd to linker before linked libraries
echo   --libs                     print linked libraries
