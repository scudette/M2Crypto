mkdir %USERPROFILE%\build\
cd %USERPROFILE%\build\ || echo "Cant switch to build directory" && exit /b 1

::Install 64 bit openssl.  Expects tar file in cwd. We delete the openssl dir to
::avoid any 32-64 contamination.
rd /q /s openssl-1.0.2f
7z x -y openssl-1.0.2f.tar

cd openssl-1.0.2f
perl Configure VC-WIN64A --prefix=%USERPROFILE%\build\Build-OpenSSL-VC-64
call ms\do_win64a.bat
nmake -f ms\ntdll.mak
nmake -f ms\ntdll.mak install

:: Set environment variables to let M2Crypto know where OpenSSL lives.
set INCLUDE=%INCLUDE%;%USERPROFILE%\build\Build-OpenSSL-VC-64\include
set LIB=%LIB%;%USERPROFILE%\build\Build-OpenSSL-VC-64\lib
set OPENSSL_INSTALL_PATH=%USERPROFILE%\build\Build-OpenSSL-VC-64
set SWIG_FEATURES=-I%USERPROFILE%\build\Build-OpenSSL-VC-64\include

:: M2Crypto development moved to https://gitlab.com/m2crypto/m2crypto but they
:: have since dropped windows and OSX support:
:: https://gitlab.com/m2crypto/m2crypto/issues/57
:: (fix windows incompatibility with ``select()``) Last comment on this thread
:: explains that windows support is not a priority. Until then we use an older
:: forked version. Hopefully we can deprecate M2Crypto soon!
git clone https://github.com/scudette/M2Crypto.git
cd M2Crypto
python setup.py install bdist_wheel

python -c "import M2Crypto" || echo "64bit M2Crypto install failed" && exit /b 1
