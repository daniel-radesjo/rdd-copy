## Process this file with automake to produce Makefile.in


bin_PROGRAMS=		rdd-copy \
			rdd-verify

lib_LTLIBRARIES=	librdd.la

librdd_la_SOURCES=	rdd.h \
			strerror.c \
			console.c \
			error.h \
			error.c \
			rdd_internals.c \
			rdd_internals.h \
			commandline.c \
			commandline.h \
			hashcontainer.h \
			hashcontainer.c \
			outfile.h \
			outfile.c \
			numparser.h \
			numparser.c \
			alignedbuf.h \
			alignedbuf.c \
			writer.h \
			writer.c \
			zlibwriter.c \
			fdwriter.c \
			filewriter.c \
			tcpwriter.c \
			safewriter.c \
			partwriter.c \
			ewfwriter.c \
			reader.h \
			reader.c \
			fdreader.c \
			filereader.c \
			atomicreader.c \
			zlibreader.c \
			faultyreader.c \
			alignedreader.c \
			filterset.h \
			filterset.c \
			filter.h \
			filter.c \
			md5streamfilter.c \
			sha1streamfilter.c \
			sha256streamfilter.c \
			sha384streamfilter.c \
			sha512streamfilter.c \
			writestreamfilter.c \
			statsblockfilter.c \
			md5blockfilter.c \
			checksumblockfilter.c \
			verifyblockfilter.c \
			copier.h \
			copier.c \
			robustcopier.c \
			simplecopier.c \
			progress.c \
			progress.h \
			msgprinter.h \
			msgprinter.c \
			stdioprinter.c \
			fileprinter.c \
			bcastprinter.c \
			logprinter.c \
			netio.c \
			netio.h
librdd_la_CFLAGS=	$(OPENSSL_CFLAGS) $(ZLIB_CFLAGS)
librdd_la_LDFLAGS=	-version-info $(LIBRDD_VERSION_INFO) $(OPENSSL_LIBS) $(LIBEWF_LIBS) $(ZLIB_LDFLAGS) -lm


rdd_copy_SOURCES=	rddcopy.c
rdd_copy_LDADD=		-L${top_builddir}/src -lrdd 

rdd_verify_SOURCES=	rddverify.c
rdd_verify_LDADD=	-L${top_builddir}/src -lrdd

man_MANS=		rdd.1 \
			rdd-copy.1 \
			rdd-verify.1

install-exec-local:
			$(INSTALL) $(srcdir)/rddi.py $(bindir)/rddi
			$(INSTALL) $(srcdir)/plot-entropy.py $(bindir)/plot-entropy
			$(INSTALL) $(srcdir)/plot-md5.py $(bindir)/plot-md5

uninstall-local:
			rm -f $(bindir)/rddi
			rm -f $(bindir)/plot-entropy
			rm -f $(bindir)/plot-md5

DISTCLEANFILES=		Makefile.in

EXTRA_DIST=		$(man_MANS) \
			rddi.py \
			plot-entropy.py \
			plot-md5.py
