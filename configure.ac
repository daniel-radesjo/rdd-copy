dnl $Id: $

dnl ------------------
dnl Ensure that a recent enough version of Autoconf is being used.
dnl ------------------
AC_PREREQ([2.60])

dnl ------------------
dnl Process any command-line arguments.
dnl Perform various initializations and verifications.
dnl Set the name of the package, its version and the email address to which
dnl users should send bug reports.
dnl ------------------
AC_INIT([rdd], [3.0.4], [rddadmin@holmes.nl])

dnl -----------------------------
dnl Set all the library versions
dnl -----------------------------
dnl Libtool has its own formal versioning system, in which library versions
dnl are described by three integers:
dnl
dnl current
dnl     The most recent interface number that this library implements.
dnl revision
dnl     The implementation number of the current interface.
dnl age
dnl     The difference between the newest and oldest interfaces that this
dnl     library implements.
dnl     In other words, the library implements all the interface numbers in
dnl     the range from number current - age to current.
dnl
dnl If you want to use libtool's versioning system, then you must specify the
dnl version information to libtool using the -version-info flag during link mode.
dnl This flag accepts an argument of the form current[:revision[:age]]. So,
dnl passing -version-info 3:12:1 sets current to 3, revision to 12, and age to 1.
dnl If either revision or age are omitted, they default to 0. Also note that
dnl age must be less than or equal to the current interface number.
dnl
dnl Here are a set of rules to help you update your library version
dnl information:
dnl
dnl   1. Start with version information of 0:0:0 for each libtool library.
dnl   2. Update the version information only immediately before a public
dnl      release of your software.
dnl      More frequent updates are unnecessary, and only guarantee that the
dnl      current interface number gets larger faster.
dnl   3. If the library source code has changed at all since the last update,
dnl      then increment revision (c:r:a becomes c:r+1:a).
dnl   4. If any interfaces have been added, removed, or changed since the
dnl      last update, increment current, and set revision to 0.
dnl   5. If any interfaces have been added since the last public release,
dnl      then increment age.
dnl   6. If any interfaces have been removed since the last public release,
dnl      then set age to 0.
dnl
dnl Never try to set the interface numbers so that they correspond to
dnl the release number of your package. This is an abuse that only fosters
dnl misunderstanding of the purpose of library versions. Instead, use the -release
dnl flag (see Release numbers), but be warned that every release of your package
dnl will not be binary compatible with any other release.
dnl 
dnl LA: I can't say I've used this propertly; setting it back to 3.0.0 (12-5-2011)
LIBRDD_VERSION_INFO=[3:0:0]
AC_SUBST([LIBRDD_VERSION_INFO])

dnl ------------------
dnl Check for this file's existence to make sure that the directory containing
dnl the source code in fact does exist.
dnl ------------------
AC_CONFIG_SRCDIR([src/rdd_internals.c])

dnl ------------------
dnl Make AC_OUTPUT create the file containing C preprocessor #define
dnl statements, and replace `@DEFS@' in generated files with `-DHAVE_CONFIG_H'
dnl instead of the value of DEFS.
dnl ------------------
AC_CONFIG_HEADERS([config.h])

dnl ------------------
dnl Run many macros required for proper operation of the generated Makefiles.
dnl ------------------
AM_INIT_AUTOMAKE

dnl Checks for options on the command-line
dnl -----------------------------
dnl tracing (default: no)
dnl -----------------------------
AC_ARG_ENABLE([tracing],
	      AC_HELP_STRING([--enable-tracing],
		             [enable tracing (default: no)]),
	      [case ${enableval} in
		yes) tracing="yes"
		     AC_DEFINE([RDD_TRACING],
			       1,
			       [Define to enable tracing.]) ;;
		no)  tracing="no" ;;
		*)   AC_MSG_ERROR([bad value ${enableval} for tracing]) ;;
	       esac],
	      [tracing="no"]
	     )
AM_CONDITIONAL(RDD_TRACING, [test "${tracing}" = "yes"])

dnl -----------------------------
dnl console (default: no)
dnl -----------------------------
AC_ARG_ENABLE([console],
	      AC_HELP_STRING([--enable-console],
		             [Use the console device /dev/tty (default: no)]),
	      [case ${enableval} in
		yes) console="yes"
		     AC_DEFINE([RDD_CONSOLE],
			       1,
			       [Define for console usage.]) ;;
		no)  console="no" ;;
		*)   AC_MSG_ERROR([bad value ${enableval} for console]) ;;
	       esac],
	      [console="no"]
	     )
AM_CONDITIONAL(RDD_CONSOLE, [test "${console}" = "yes"])

dnl -----------------------------
dnl gui (default: no) -- not functional because gui isn't up-to-date 
dnl and nonfunctional
dnl -----------------------------
dnl AC_ARG_ENABLE([gui],
dnl	      AC_HELP_STRING([--enable-gui],
dnl		             [Enable GTK-2.0 GUI for rdd (default: no)]),
dnl	      [case ${enableval} in
dnl		yes) gui="yes"
dnl		     AC_DEFINE([RDD_GUI],
dnl			       1,
dnl			       [Define for GUI support.])
dnl		     dnl ------------------
dnl		     dnl Check libglade-2.0 is available.
dnl		     dnl ------------------
dnl		     PKG_CHECK_MODULES([LIBGLADE], [libglade-2.0 >= 2.6.0])
dnl
dnl		     dnl ------------------
dnl		     dnl Test for GTK+, and define GTK_CFLAGS and GTK_LIBS
dnl		     dnl ------------------
dnl		     AM_PATH_GTK_2_0 ;;
dnl		no)  gui="no" ;;
dnl		*)   AC_MSG_ERROR([bad value ${enableval} for gui]) ;;
dnl	       esac],
dnl	      [gui="no"]
dnl	     )
dnl AM_CONDITIONAL(RDD_GUI, [test "${gui}" = "yes"])

dnl -----------------------------
dnl Enable debugging (default: no)
dnl -----------------------------
NFI_DEBUG

dnl ------------------
dnl Check for C compiler and preprocessor
dnl ------------------
AC_PROG_CC
AC_PROG_CPP

dnl ------------------
dnl If the user hasn't specified CFLAGS and the compiler is gcc:
dnl   use -O2 and some warning flags in release mode.
dnl   use -O0, -g and some warning flags in debug mode.
dnl If the user has specified an include directory add it to C(XX)FLAGS.
dnl ------------------
NFI_CFLAGS(-I\$(top_srcdir)/src)

dnl ------------------
dnl Enable checking for dlopen support.
dnl Change the default behaviour for AC_PROG_LIBTOOL to disable static
dnl libraries. The user may still override this default by specifying
dnl `--enable-static'.
dnl Add support for the `--enable-shared' and `--disable-shared' configure
dnl flags.
dnl ------------------
AC_LIBTOOL_DLOPEN
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_SUBST([LIBTOOL_DEPS])

dnl ------------------
dnl Check availability of pkg-config
dnl ------------------
PKG_PROG_PKG_CONFIG

dnl Checks for header files.
dnl ------------------
dnl For each given system header file header-file in the whitespace-separated
dnl argument list that exists, define HAVE_header-file (in all capitals)
dnl ------------------
AC_CHECK_HEADERS([arpa/inet.h \
		  fcntl.h \
		  limits.h \
		  memory.h \
		  netdb.h \
		  netinet/in.h \
		  stddef.h \
		  stdint.h \
		  stdlib.h \
		  string.h \
		  sys/socket.h \
		  sys/time.h \
		  unistd.h \
		  sys/utsname.h \
		  pwd.h])

dnl ------------------
dnl If the compiler has the complex math functions, define HAVE_COMPLEX_MATH1.
dnl ------------------
dnl AC_CXX_HAVE_COMPLEX_MATH1

dnl ------------------
dnl If sys/wait.h exists and is compatible with Posix, define HAVE_SYS_WAIT_H.
dnl ------------------
AC_HEADER_SYS_WAIT

dnl ------------------
dnl Define STDC_HEADERS if the system has ANSI C header files.
dnl ------------------
AC_HEADER_STDC

dnl ------------------
dnl If the C compiler does not fully support the ANSI C qualifier const,
dnl define const to be empty.
dnl ------------------
AC_C_CONST

dnl ------------------
dnl Define mode_t to a suitable type, if standard headers do not define it.
dnl ------------------
AC_TYPE_MODE_T

dnl ------------------
dnl Define off_t to a suitable type, if standard headers do not define it.
dnl ------------------
AC_TYPE_OFF_T

dnl ------------------
dnl Define pid_t to a suitable type, if standard headers do not define it.
dnl ------------------
AC_TYPE_PID_T

dnl ------------------
dnl Define size_t to a suitable type, if standard headers do not define it.
dnl ------------------
AC_TYPE_SIZE_T

dnl ------------------
dnl Define ssize_t to a suitable type, if standard headers do not define it.
dnl ------------------
AC_TYPE_SSIZE_T

dnl ------------------
dnl If the error_at_line function is not found, require an AC_LIBOBJ replacement of `error'.
dnl ------------------
AC_FUNC_ERROR_AT_LINE

dnl ------------------
dnl This macro checks for the fork and vfork functions.
dnl ------------------
AC_FUNC_FORK

dnl ------------------
dnl If the malloc function is compatible with the GNU C library malloc (i.e., `malloc (0)' returns a valid pointer), define HAVE_MALLOC to 1.
dnl ------------------
AC_FUNC_MALLOC

dnl ------------------
dnl Checs for functions
dnl ------------------
AC_CHECK_FUNCS([gethostname gettimeofday inet_ntoa memset socket strchr strerror strrchr uname])

dnl ------------------
dnl If a program may include both `time.h' and `sys/time.h', define
dnl TIME_WITH_SYS_TIME.
dnl If `time.h' does not define struct tm, define TM_IN_SYS_TIME, which
dnl means that including `sys/time.h' had better define struct tm.
dnl ------------------
AC_HEADER_TIME
AC_STRUCT_TM

dnl ------------------
dnl Check the type ptrdiff_t.
dnl ------------------
AC_CHECK_TYPES([ptrdiff_t])

dnl ------------------
dnl Check OpenSSL is available.
dnl ------------------
PKG_CHECK_MODULES([OPENSSL],
		  [openssl >= 0.9.6],
		  [AC_DEFINE([HAVE_OPENSSL],
			    1,
			    [Define for OPENSSL support.])]
		 )



dnl ------------------
dnl Arrange large file support
dnl ------------------
AC_SYS_LARGEFILE

dnl ------------------
dnl Check zlib is available.
dnl ------------------
CHECK_ZLIB([1.2.1])

dnl ------------------
dnl Check LibEWF is available.
dnl ------------------
PKG_CHECK_MODULES([LIBEWF],
		  [libewf >= 1.0.4],
		  [AC_DEFINE([HAVE_LIBEWF],
			    1,
			    [Define for LIBEWF support.])]
		 )

dnl ------------------
dnl Create a generic PACKAGE-config file that has all the things that you
dnl want, hmm, well, atleast it has --cflags, --version, --libs.
dnl Ahhm, did you see ac_path_generic in the autoconf-archive? ;-)
dnl ------------------
AC_CREATE_GENERIC_CONFIG([rdd])

DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(ON)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN([rdd], [rdd.doxyfile])

dnl ------------------
dnl Make AC_OUTPUT create each `file' by copying an input file (by default
dnl `file.in'), substituting the output variable values.
dnl ------------------
AC_CONFIG_FILES([Makefile \
		 rdd.pc \
		 rdd.spec \
		 src/Makefile \
		 test/Makefile \
		 test/trunmd5blockfilter.sh \
		 test/tpython_tcpwriter.sh \
		 test/tmsgprinter.sh])

dnl ------------------
dnl Generate `config.status' and launch it.
dnl ------------------
AC_OUTPUT

dnl ------------------
dnl Create a generic report of the package configuration
dnl ------------------
AC_CREATE_REPORT
