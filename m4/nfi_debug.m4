dnl -----------------------------
dnl Enable debugging (default: no)
dnl -----------------------------
AC_DEFUN([NFI_DEBUG],
	 [
		AC_ARG_ENABLE([debug],
			      AS_HELP_STRING([--enable-debug], [Enable debugging (default is NO)]),
			      [case $enableval in
			       yes) debug_build="yes"
				AC_DEFINE([DEBUG_BUILD], 1, [Enable debugging]) ;;
			       no)  debug_build="no" ;;
			       *)   AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
			      esac],
			      [debug_build="no"]
		)
		AM_CONDITIONAL(DEBUG_BUILD, [test "$debug_build" = "yes"])
	]
)
