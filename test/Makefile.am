## Process this file with automake to produce Makefile.in

AM_CFLAGS=			$(OPENSSL_CFLAGS)

AM_LDFLAGS=			$(OPENSSL_LIBS)

DISTCLEANFILES=			Makefile.in

TESTS=				tbuildtestfile \
				test001 \
				test002 \
				test003 \
				test004 \
				test005 \
				test006 \
				tatomicreader \
				tbcastprinter \
				talignedbuf \
				tcommandline \
				tchecksumblockfilter \
				tcopier \
				tewfwriter \
				tstrerror \
				tfaultyreader \
				tfilter \
				thashcontainer \
				tmain \
				tmd5streamfilter \
				tmsgprinter.sh \
				tnetio \
				tnewwriter \
				tnumparser \
				tpython_tcpwriter.sh \
				trunmd5blockfilter.sh \
				tshafilters \
				tsha1streamfilter \
				tsha256streamfilter \
				tsha384streamfilter \
				tsha512streamfilter \
				trunmd5blockfilter.sh \
				tpython_tcpwriter.sh \
				tmsgprinter.sh \
				tewfwriter \
				tfdwriter \
				tfilewriter \
				trdd_internals \
				tsafewriter \
				thashcontainer \
				tpartwriter \
				ttcpwriter \
				tzlibwriter \
				twriter \
				tnetio \
				tmain

noinst_PROGRAMS=		tbuildtestfile \
				tstrerror \
				tatomicreader \
				tbcastprinter \
				tcommandline \
				tchecksumblockfilter \
				tcompress \
				tcopier \
				tfaultyreader \
				tfile \
				tfiledesc \
				tfilter \
				tsafe \
				tpart \
				tnumparser \
				talignedbuf \
				tnewwriter \
				tshafilters \
				tmd5streamfilter \
				tsha1streamfilter \
				tsha256streamfilter \
				tsha384streamfilter \
				tsha512streamfilter \
				treader \
				tmd5blockfilter \
				tpython_tcpwriter \
				tmsgprinter \
				tewfwriter \
				tfaultyreader \
				tfdwriter \
				tfilewriter \
				trdd_internals \
				tpartwriter \
				tsafewriter \
				thashcontainer \
				ttcpwriter \
				tzlibwriter \
				twriter \
				tnetio \
				tmain

WRITERCORE=			core_writer.c \
				rddtest.c \
				rddtest.h


tstrerror_SOURCES=		tstrerror.c testhelper.h
tstrerror_LDADD=		-L${top_builddir}/src -lrdd

tatomicreader_SOURCES=	tatomicreader.c testhelper.h mockreader.c mockreader.h
tatomicreader_LDADD=	-L${top_builddir}/src -lrdd

tbcastprinter_SOURCES= tbcastprinter.c testhelper.h mockprinter.c mockprinter.h
tbcastprinter_LDADD=	-L${top_builddir}/src -lrdd

tcompress_SOURCES=		$(WRITERCORE) tcompress.c
tcompress_LDADD=		-L${top_builddir}/src -lrdd

tcopier_SOURCES=		 tcopier.c mockcopier.c mockcopier.h mockreader.c mockreader.h
tcopier_LDADD= 			-L${top_builddir}/src -lrdd

tfile_SOURCES=			$(WRITERCORE) tfile.c
tfile_LDADD=			-L${top_builddir}/src -lrdd

tfiledesc_SOURCES=		$(WRITERCORE) tfiledesc.c
tfiledesc_LDADD=		-L${top_builddir}/src -lrdd

tfilter_SOURCES=		tfilter.c testhelper.h mockstreamfilter.c mockstreamfilter.h mockblockfilter.c mockblockfilter.h
tfilter_LDADD=			-L${top_builddir}/src -lrdd

tsafe_SOURCES=			$(WRITERCORE) tsafe.c
tsafe_LDADD=			-L${top_builddir}/src -lrdd

tpart_SOURCES=			$(WRITERCORE) tpart.c
tpart_LDADD=			-L${top_builddir}/src -lrdd

tnumparser_SOURCES=		tnumparser.c
tnumparser_LDADD=		-L${top_builddir}/src -lrdd

talignedbuf_SOURCES=		talignedbuf.c
talignedbuf_LDADD=		-L${top_builddir}/src -lrdd

tcommandline_SOURCES=		tcommandline.c testhelper.h
tcommandline_LDADD=		-L${top_builddir}/src -lrdd

tchecksumblockfilter_SOURCES=	tchecksumblockfilter.c testhelper.h
tchecksumblockfilter_LDADD=		-L${top_builddir}/src -lrdd

tnewwriter_SOURCES=		tnewwriter.c
tnewwriter_LDADD=		-L${top_builddir}/src -lrdd

tshafilters_SOURCES=		tshafilters.c
tshafilters_LDADD=		-L${top_builddir}/src -lrdd
	
tmd5streamfilter_SOURCES=	tmd5streamfilter.c testhelper.h
tmd5streamfilter_LDADD=		-L${top_builddir}/src -lrdd

tsha1streamfilter_SOURCES= 	tsha1streamfilter.c testhelper.h
tsha1streamfilter_LDADD=	-L${top_builddir}/src -lrdd

tsha256streamfilter_SOURCES= 	tsha256streamfilter.c testhelper.h
tsha256streamfilter_LDADD=	-L${top_builddir}/src -lrdd

tsha384streamfilter_SOURCES= 	tsha384streamfilter.c testhelper.h
tsha384streamfilter_LDADD=	-L${top_builddir}/src -lrdd

tsha512streamfilter_SOURCES= 	tsha512streamfilter.c testhelper.h
tsha512streamfilter_LDADD=	-L${top_builddir}/src -lrdd

treader_SOURCES=		treader.c
treader_LDADD=			-L${top_builddir}/src -lrdd

tbuildtestfile_SOURCES=		tbuildtestfile.c
tbuildtestfile_LDADD=		-L${top_builddir}/src -lrdd

tmd5blockfilter_SOURCES=	tmd5blockfilter.c
tmd5blockfilter_LDADD=		-L${top_builddir}/src -lrdd

tpython_tcpwriter_SOURCES=	tpython_tcpwriter.c
tpython_tcpwriter_LDADD=	-L${top_builddir}/src -lrdd

tmsgprinter_SOURCES=		tmsgprinter.c
tmsgprinter_LDADD=		-L${top_builddir}/src -lrdd

tewfwriter_SOURCES=		tewfwriter.c testhelper.h
tewfwriter_LDADD=		-L${top_builddir}/src -lrdd

tfaultyreader_SOURCES=		tfaultyreader.c testhelper.h mockreader.c mockreader.h
tfaultyreader_LDADD=		-L${top_builddir}/src -lrdd

tfdwriter_SOURCES=		tfdwriter.c testhelper.h
tfdwriter_LDADD=		-L${top_builddir}/src -lrdd

tfilewriter_SOURCES=		tfilewriter.c testhelper.h
tfilewriter_LDADD=		-L${top_builddir}/src -lrdd

tpartwriter_SOURCES=		tpartwriter.c testhelper.h
tpartwriter_LDADD=		-L${top_builddir}/src -lrdd

trdd_internals_SOURCES=		trdd_internals.c testhelper.h
trdd_internals_LDADD=		-L${top_builddir}/src -lrdd

tsafewriter_SOURCES=		tsafewriter.c testhelper.h
tsafewriter_LDADD=		-L${top_builddir}/src -lrdd

thashcontainer_SOURCES=		thashcontainer.c testhelper.h
thashcontainer_LDADD=		-L${top_builddir}/src -lrdd

ttcpwriter_SOURCES=		ttcpwriter.c testhelper.h
ttcpwriter_LDADD=		-L${top_builddir}/src -lrdd -lpthread

tzlibwriter_SOURCES=		tzlibwriter.c testhelper.h
tzlibwriter_LDADD=		-L${top_builddir}/src -lrdd -lpthread

twriter_SOURCES=		twriter.c testhelper.h
twriter_LDADD=			-L${top_builddir}/src -lrdd

tnetio_SOURCES=			tnetio.c testhelper.h
tnetio_LDADD=			-L${top_builddir}/src -lrdd

tmain_SOURCES=			tmain.c testhelper.h
tmain_LDADD=			-L${top_builddir}/src -lrdd -lpthread
