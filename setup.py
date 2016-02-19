#!/usr/bin/env python
r"""
Distutils/setuptools installer for M2Crypto.

Copyright (c) 1999-2004, Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.

Copyright 2008-2009 Heikki Toivonen. All rights reserved.
Copyright 2014 Martin Paljak


Building from source: Use the following script...

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

git clone https://github.com/scudette/M2Crypto.git

cd M2Crypto
python setup.py install bdist_wheel

"""
import glob
import re
import shutil
import subprocess
import os, sys
from setuptools import setup
from setuptools.command import build_ext
from setuptools.command import sdist

from setuptools import Extension
from distutils.spawn import find_executable


# Allow the user to supply the actual openssl installation path.
if os.name == "nt":
    OPENSSL_INSTALL_PATH = os.environ.get("OPENSSL_INSTALL_PATH",
                                          r"c:\pkg")
    OPENSSL_RUNTIME_LIBS = [
        os.path.join(OPENSSL_INSTALL_PATH, "bin", "*.dll"),
    ]
else:
    OPENSSL_INSTALL_PATH = os.environ.get("OPENSSL_INSTALL_PATH",
                                          "/usr/")

    OPENSSL_RUNTIME_LIBS = [
        os.path.join(OPENSSL_INSTALL_PATH, "lib", "libssl.so*"),
        os.path.join(OPENSSL_INSTALL_PATH, "lib", "libcrypto.so*"),
    ]

DEB_HOST_MULTIARCH = None
try:
    DEB_HOST_MULTIARCH = subprocess.check_output(
        ["dpkg-architecture", "-qDEB_HOST_MULTIARCH"]).strip()

    DEB_HOST_MULTIARCH_PATH = os.path.join("/usr/lib/", DEB_HOST_MULTIARCH)
    OPENSSL_RUNTIME_LIBS.extend([
        os.path.join(DEB_HOST_MULTIARCH_PATH, "libssl.so*"),
        os.path.join(DEB_HOST_MULTIARCH_PATH, "libcrypto.so*"),
    ])
except Exception:
    pass


def get_all_globs(globs):
    result = []
    for exp in globs:
        result.extend(glob.glob(exp))

    return result


class _M2CryptoBuildExt(build_ext.build_ext):
    '''Specialization of build_ext to enable swig_opts to inherit any
    include_dirs settings made at the command line or in a setup.cfg file'''

    def initialize_options(self):
        '''Overload to enable custom OpenSSL settings to be picked up'''

        build_ext.build_ext.initialize_options(self)

        # openssl is the attribute corresponding to openssl directory prefix
        # command line option
        if os.name == 'nt':
            self.libraries = ['ssleay32', 'libeay32']
            self.openssl = OPENSSL_INSTALL_PATH
        else:
            self.libraries = ['ssl', 'crypto']
            self.openssl = OPENSSL_INSTALL_PATH

    def add_multiarch_paths(self):
        # Debian/Ubuntu multiarch support.
        # https://wiki.ubuntu.com/MultiarchSpec
        if not find_executable('dpkg-architecture'):
            return
        tmpfile = os.path.join(self.build_temp, 'multiarch')
        if not os.path.exists(self.build_temp):
            os.makedirs(self.build_temp)
        ret = os.system(
            'dpkg-architecture -qDEB_HOST_MULTIARCH > %s 2> /dev/null' %
            tmpfile)
        try:
            if ret >> 8 == 0:
                with open(tmpfile) as fp:
                    multiarch_path_component = fp.readline().strip()
                self.library_dirs.append(
                    os.path.join('/usr/lib/' + multiarch_path_component))
                self.include_dirs.append(
                    os.path.join('/usr/include/' + multiarch_path_component))
        finally:
            os.unlink(tmpfile)

    def finalize_options(self):
        '''Overloaded build_ext implementation to append custom openssl
        include file and library linking options'''

        build_ext.build_ext.finalize_options(self)

        self.add_multiarch_paths()

        opensslIncludeDir = os.path.join(self.openssl, 'include')
        opensslLibraryDir = os.path.join(self.openssl, 'lib')

        self.include_dirs += [os.path.join(self.openssl, opensslIncludeDir),
                              os.path.join(os.getcwd(), 'SWIG')]

        if sys.platform == 'cygwin':
            # Cygwin SHOULD work (there's code in distutils), but
            # if one first starts a Windows command prompt, then bash,
            # the distutils code does not seem to work. If you start
            # Cygwin directly, then it would work even without this change.
            # Someday distutils will be fixed and this won't be needed.
            self.library_dirs += [os.path.join(self.openssl, 'bin')]

        self.library_dirs += [os.path.join(self.openssl, opensslLibraryDir)]


if sys.platform == 'darwin':
    my_extra_compile_args = ["-Wno-deprecated-declarations"]
else:
    my_extra_compile_args = []

m2crypto = Extension(name='M2Crypto.__m2crypto',
                     sources=['SWIG/_m2crypto_wrap.c'],
                     extra_compile_args=['-DTHREADING'] + my_extra_compile_args,
                    )


class CustomSDist(sdist.sdist):
    """Swig the sources when creating the sdist.

    When we install we only depend on the generated C files and not on
    swig. This makes it much easier to install since we do not need to have swig
    installed. Additionally, this version of M2Crypto requires an older version
    of swig or it will produce broken code.
    """
    def run(self):
        # Check the swig version.
        output = subprocess.check_output(["swig", "-version"])
        m = re.search("SWIG Version +([^ ]+)", output)
        if not m:
            raise RuntimeError("Swig version must be < 3.0.2.")

        swig_opts = ["swig", "-python"]
        if DEB_HOST_MULTIARCH:
            swig_opts.append("-I/usr/include/%s" % DEB_HOST_MULTIARCH)

        swig_opts.append("-I%s" % os.path.join(OPENSSL_INSTALL_PATH, 'include'))
        swig_opts.append("-I%s" % os.path.join(OPENSSL_INSTALL_PATH, 'include',
                                               "openssl"))
        swig_opts.append('-includeall')
        swig_opts.append('-modern')

        subprocess.check_call(
            swig_opts + ["-o", "SWIG/_m2crypto_wrap.c", "SWIG/_m2crypto.i"])

        # Clean up any residual .so .dll etc:
        for f in get_all_globs(["M2Crypto/*.dll",
                                "M2Crypto/*.so",
                                "M2Crypto/*.dylib"]):
            os.unlink(f)

        sdist.sdist.run(self)


def copy_dlls():
    for dep in get_all_globs(OPENSSL_RUNTIME_LIBS):
        print "Copy %s" % dep
        shutil.copy(dep, "M2Crypto")

copy_dlls()


setup(name='GRR-M2Crypto',
      version='0.22.6.post2',
      description='M2Crypto: A Python crypto and SSL toolkit',
      long_description='''\
M2Crypto is the most complete Python wrapper for OpenSSL featuring RSA, DSA,
DH, EC, HMACs, message digests, symmetric ciphers (including AES); SSL
functionality to implement clients and servers; HTTPS extensions to Python's
httplib, urllib, and xmlrpclib; unforgeable HMAC'ing AuthCookies for web
session management; FTP/TLS client and server; S/MIME; ZServerSSL: A HTTPS
server for Zope and ZSmime: An S/MIME messenger for Zope. M2Crypto can also be
used to provide SSL for Twisted. Smartcards supported through the Engine
interface.

This is a binary wheel distribution release by the GRR team:
https://github.com/google/grr
''',
      license='MIT',
      platforms=['any'],
      author='Ng Pheng Siong',
      author_email='ngps at sandbox rulemaker net',
      maintainer='Martin Paljak',
      maintainer_email='martin@martinpaljak.net',
      url='https://github.com/martinpaljak/M2Crypto',
      packages=['M2Crypto', 'M2Crypto.SSL'],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: OS Independent',
          'Programming Language :: C',
          'Programming Language :: Python',
          'Topic :: Security :: Cryptography',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Programming Language :: Python :: 2.5',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: Implementation :: CPython'
      ],

      ext_modules=[m2crypto],
      test_suite='test.alltests.suite',
      zip_safe=False,
      include_package_data=True,
      cmdclass=dict(
          build_ext=_M2CryptoBuildExt,
          sdist=CustomSDist,
      ),
      # Copy the openssl dlls into the package. This ensures they are
      # included in binary packages.
      package_data={
          "M2Crypto": [r"*.dll", "*.so*", "*.dylib"],
      }
     )
