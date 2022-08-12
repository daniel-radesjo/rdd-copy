dnl @synopsis AC_CREATE_REPORT
dnl
dnl Creates a generic report of the package configuration.
dnl
dnl @author Martijn Ras <Martijn.Ras@GMail.com>
dnl
AC_DEFUN([AC_CREATE_REPORT],
[
	config_date=`date`
	compiler_version=`c++ --version | head -1`
	distro=`uname -nmrsp`

	echo "----------------------------------------------------------------------"
	echo "Package configuration summary"
	echo "----------------------------------------------------------------------"
	echo "operating system / distro: $distro"
	echo "compiler version:          $compiler_version"
	echo
	echo "configure date:            $config_date"
	echo "installation path:         $prefix"
	echo
	echo "CFLAGS                     $CFLAGS"
	echo "CXXFLAGS                   $CXXFLAGS"
	echo "LDFLAGS                    $LDFLAGS"
	echo "LIBS                       $LIBS"
	echo "----------------------------------------------------------------------"
	echo
	echo "Now type 'make' to build this package."
	echo
])
