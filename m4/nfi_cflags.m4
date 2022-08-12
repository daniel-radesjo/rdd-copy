dnl ------------------
dnl If the user hasn't specified CFLAGS and the compiler is gcc:
dnl   use -O2 and some warning flags in release mode.
dnl   use -O0, -g and some warning flags in debug mode.
dnl If the user has specified an include directory add it to C(XX)FLAGS.
dnl ------------------
AC_DEFUN([NFI_CFLAGS],
	 [
		if test -n "${GCC}"
		then
			AC_MSG_RESULT([appending NFI cflags for GCC])
			CFLAGS="-Wall -Wmissing-prototypes"
			CXXFLAGS="-Wall"
			LDFLAGS="" 
			LIBS="-lgcc" 
			if test $# -eq 1
			then
				CFLAGS="${CFLAGS} $1"
				CXXFLAGS="${CXXFLAGS} $1"
			fi 
			if test "$debug_build" = "yes"
			then
				CFLAGS="${CFLAGS} -g -O0"
				CXXFLAGS="${CXXFLAGS} -g -O0"
				LFGLAGS="${LFGLAGS} -g"
			else
				CFLAGS="${CFLAGS} -O2 -DNDEBUG"
				CXXFLAGS="${CXXFLAGS} -O2 -DNDEBUG"
			fi
		else
			AC_MSG_RESULT([appending NFI cflags for non-GCC])
			CFLAGS=""
			CXXFLAGS=""
			if test $# -eq 1
			then
				CFLAGS="$1"
				CXXFLAGS="$1"
			fi 
			LIBS=""
			LDFLAGS=""
		fi
		AC_SUBST(CFLAGS)
		AC_SUBST(CXXFLAGS)
		AC_SUBST(LDFLAGS)
		AC_SUBST(LIBS)
	 ]
)
