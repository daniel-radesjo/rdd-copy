## Process this file with automake to produce Makefile.in

include			doxygen.mk

ACLOCAL_AMFLAGS=	-I ./m4

SUBDIRS=		src test
#if RDD_GUI
#SUBDIRS+=		gui
#endif

clean-local:
			-rm -rf autom4te*.cache doxygen-doc

DISTCLEANFILES=		aclocal.m4 \
			config.guess \
			config.h.in* \
			config.log \
			config.status \
			config.sub \
			configure \
			depcomp \
			rdd-config \
			rdd-*.tar.* \
			install-sh \
			ltmain.sh \
			Makefile.in \
			missing \
			mkinstalldirs

if DX_COND_html
html_DATA=		@DX_DOCDIR@/html/*

$(html_DATA):		doxygen-run
endif

EXTRA_DIST= 		test/test001 \
			test/test002 \
			test/test003 \
			test/test004 \
			test/test005 \
			test/test006 \
			test/blockhash.py \
			test/driver-writer \
			test/errorcodes.txt \
			test/simfile.txt \
			test/tmsgprinter.py \
			test/tmsgprinter.sh \
			test/tmsgprinter.sh.in \
			test/trunmd5blockfilter.sh \
			test/trunmd5blockfilter.sh.in \
			test/tpython_tcpwriter.py \
			test/tpython_tcpwriter.sh \
			test/tpython_tcpwriter.sh.in \
			test/8-jpeg-search.dd \
			test/existing_file.E01 \
			test/image.img \
			test/netio_info \
			test/netio_info_empty_filename \
			test/netio_info_filename_len_0 \
			test/netio_info_filename_len_too_long \
			test/netio_info_filename_not_terminated \
			test/simpletestfile.txt \
			test/tools/rfile-cat \
			${DX_CONFIG} \
			${html_DATA}

MOSTLYCLEANFILES=	${DX_CLEANFILES}

rpm:			dist-bzip2
			rpmbuild -ta ${distdir}.tar.bz2
