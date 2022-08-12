/*
 * Copyright (c) 2002 - 2010, Netherlands Forensic Institute
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


/* A unit-test for netio. This file replaces the original ttcpwriter.c file, which is now called tpython_tcpwriter.c.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>



#include "rdd.h"
#include "netio.c"
#include "msgprinter.h"

#include "testhelper.h"

static char *progname;

static int
test_pack_netnum_packed_null()
{
	CHECK_UINT(RDD_BADARG, pack_netnum(0, 35));
	return 1;
}

static int 
test_pack_netnum_0()
{
	struct netnum packed;
	CHECK_UINT(RDD_OK, pack_netnum(&packed, 0x0ULL));
	CHECK_UINT(0x0, packed.hi);
	CHECK_UINT(0x0, packed.lo);	

	return 1;
}

static int 
test_pack_netnum()
{
	struct netnum packed;
	CHECK_UINT(RDD_OK, pack_netnum(&packed, 0x10aabbccddULL));
	CHECK_UINT(0x10000000U, packed.hi);
	CHECK_UINT(0xddccbbaaU, packed.lo);	

	return 1;
}

static int 
test_pack_netnum_large()
{
	struct netnum packed;
	CHECK_UINT(RDD_OK, pack_netnum(&packed, 0xffffffffffffffffULL));
	CHECK_UINT(0xffffffff, packed.hi);
	CHECK_UINT(0xffffffff, packed.lo);	

	return 1;
}

static int
test_unpack_netnum_packed_null()
{
	rdd_count_t result;
	CHECK_UINT(RDD_BADARG, unpack_netnum(0, &result));
	return 1;
}

static int
test_unpack_netnum_num_null()
{
	struct netnum packed;
	CHECK_UINT(RDD_BADARG, unpack_netnum(&packed, 0));
	return 1;
}

static int 
test_unpack_netnum_0()
{
	struct netnum packed;
	packed.hi = 0;
	packed.lo = 0;
	rdd_count_t result;
	CHECK_UINT(RDD_OK, unpack_netnum(&packed, &result));
	CHECK_UINT64(0x0ULL, result);

	return 1;
}

static int 
test_unpack_netnum()
{
	struct netnum packed;
	packed.hi = 0x10000000U;
	packed.lo = 0xddccbbaaU;
	rdd_count_t result;
	CHECK_UINT(RDD_OK, unpack_netnum(&packed, &result));
	CHECK_UINT64(0x10aabbccddULL, result);
	

	return 1;
}

static int 
test_unpack_netnum_large()
{
	struct netnum packed;
	packed.hi = 0xffffffff;
	packed.lo = 0xffffffff;
	rdd_count_t result;
	CHECK_UINT(RDD_OK, unpack_netnum(&packed, &result));
	CHECK_UINT64(0xffffffffffffffffULL, result);	

	return 1;
}

static int
test_rdd_send_info_writer_null()
{
	CHECK_UINT(RDD_BADARG, rdd_send_info(0, "blablabla", 0, 0, 0, 0, 0));
	return 1;
}

static int
test_rdd_send_info_filename_null()
{
	RDD_WRITER * writer;

	// use file writer to test
	CHECK_UINT(RDD_OK, rdd_open_file_writer(&writer, "tnetio_send_info")); 

	CHECK_UINT(RDD_BADARG, rdd_send_info(writer, 0, 0, 0, 0, 0, 0));

	CHECK_UINT(RDD_OK, rdd_writer_close(writer));


	return 1;
}	

static int
test_rdd_send_info_filename_too_large()
{
	RDD_WRITER * writer;

	// use file writer to test
	CHECK_UINT(RDD_OK, rdd_open_file_writer(&writer, "tnetio_send_info")); 

	CHECK_UINT(RDD_ERANGE, rdd_send_info(writer, 
	"this filename is way to large to fit into 256 bytes, but only as long as we ar"
	"e adding this addition: gwdgrterjylke7rlkylunjlrkulkjrulkrlukjnlkrtulkjnrtlukn"
	"jlkrlukjrnlutkjnlktrnulkjrtluker6poyjhrudhjh;lr78[uiyt[8poj[ytp8ok[pouhi.[kpre"
	"sdty;ljhpyre09u-09t-0u9-0tr89-iu;li;l0-oji6[py9tk;ljhi';lk';9898!!!!!", 0x38, 0x78, 0x289, 0x1, 0x938));

	CHECK_UINT(RDD_OK, rdd_writer_close(writer));


	return 1;

}

static int
test_rdd_send_info()
{
	RDD_WRITER * writer;

	// use file writer to test
	CHECK_UINT(RDD_OK, rdd_open_file_writer(&writer, "netio_info_result")); 

	CHECK_UINT_GOTO(RDD_OK, rdd_send_info(writer, "filename_to_send", 0x38, 0x78, 0x289, 0x1, 0x938));

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp netio_info_result netio_info"));

	CHECK_EXITSTATUS(EXIT_SUCCESS, system("rm -f netio_info_result"));

	return 1;
error:
	IGNORE_RESULT(system("rm -f netio_info_result"));
	return 0;

}

static int
test_receive_reader_null() 
{
	unsigned char buffer[10];
	CHECK_UINT(RDD_BADARG, receive(0, buffer, sizeof(buffer)));

	return 1;
}

static int
test_receive_buffer_null()
{
	RDD_READER * reader;

	// use file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info", 0)); 

	CHECK_UINT(RDD_BADARG, receive(reader, 0, 10));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));

	return 1;
}

static int
test_receive()
{
	RDD_READER * reader;

	unsigned char expected[] = {
		0x0, 0x0, 0x0, 0x11, 0x0, 0x0, 0x0, 0x0, // file name length (0x11=17)
		0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0, // file size
		0x0, 0x0, 0x0, 0x78, 0x0, 0x0, 0x0, 0x0, // block size
		0x0, 0x0, 0x2, 0x89, 0x0, 0x0, 0x0, 0x0, // split size
		0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,  // ewf
		0x0, 0x0, 0x9, 0x38, 0x0, 0x0, 0x0, 0x0, // flags
		'f', 'i', 'l', 'e', 'n', 'a', 'm', 'e', '_', 't', 'o', '_', 's', 'e', 'n', 'd', '\0'}; // file name
	unsigned char buffer[sizeof(expected)];

	// use file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info", 0)); 

	CHECK_UINT(RDD_OK, receive(reader, buffer, sizeof(buffer)));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));

	CHECK_UCHAR_ARRAY(expected, buffer, sizeof(buffer));

	return 1;

}

static int
test_receive_read_less_bytes()
{
	RDD_READER * reader;

	unsigned char expected[] = {
		0x0, 0x0, 0x0, 0x11, 0x0, 0x0, 0x0, 0x0, // file name length (0x11=17)
		0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0, // file size
		0x0, 0x0, 0x0, 0x78, 0x0, 0x0, 0x0, 0x0, // block size
		0x0, 0x0, 0x2, 0x89, 0x0, 0x0, 0x0, 0x0, // split size
		0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,  // ewf
		0x0, 0x0, 0x9, 0x38, 0x0, 0x0, 0x0, 0x0, // flags
		'f', 'i', 'l', 'e', 'n', 'a', 'm', 'e', '_', 't', 'o', '_', 's', 'e', 'n', 'd', '\0'}; // file name
	unsigned char buffer[sizeof(expected)];

	// use file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info", 0)); 

	CHECK_UINT(RDD_OK, receive(reader, buffer, sizeof(buffer) - 10));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));

	CHECK_UCHAR_ARRAY(expected, buffer, sizeof(buffer) - 10);

	return 1;

}

static int
test_receive_too_many_bytes()
{
	RDD_READER * reader;


	unsigned char buffer[70]; // file contains 65 bytes

	// use file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info", 0)); 

	CHECK_UINT(RDD_ESYNTAX, receive(reader, buffer, sizeof(buffer)));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));

	return 1;

}

static int
test_rdd_recv_info_reader_null()
{
	char * filename;
	rdd_count_t file_size;
	rdd_count_t block_size;
	rdd_count_t split_size;
	int ewf;
	unsigned int flags;


	CHECK_UINT(RDD_BADARG, rdd_recv_info(0, &filename, &file_size, &block_size, &split_size, &ewf, &flags));
	return 1;
}

static int
test_rdd_recv_info_filename_null()
{
	RDD_READER * reader;
	rdd_count_t file_size;
	rdd_count_t block_size;
	rdd_count_t split_size;
	int ewf;
	unsigned int flags;

	// user file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info", 0));

	CHECK_UINT(RDD_BADARG, rdd_recv_info(reader, 0, &file_size, &block_size, &split_size, &ewf, &flags));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));

	return 1;	
}

static int
test_rdd_recv_info_file_size_null()
{
	RDD_READER * reader;
	char * filename;
	rdd_count_t block_size;
	rdd_count_t split_size;
	int ewf;
	unsigned int flags;

	// user file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info", 0));

	CHECK_UINT(RDD_BADARG, rdd_recv_info(reader, &filename, 0, &block_size, &split_size, &ewf, &flags));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));

	return 1;	
}

static int
test_rdd_recv_info_block_size_null()
{
	RDD_READER * reader;
	char * filename;
	rdd_count_t file_size;
	rdd_count_t split_size;
	int ewf;
	unsigned int flags;

	// user file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info", 0));

	CHECK_UINT(RDD_BADARG, rdd_recv_info(reader, &filename, &file_size, 0, &split_size, &ewf, &flags));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));

	return 1;	
}

static int
test_rdd_recv_info_split_size_null()
{
	RDD_READER * reader;
	char * filename;
	rdd_count_t file_size;
	rdd_count_t block_size;
	int ewf;
	unsigned int flags;

	// user file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info", 0));

	CHECK_UINT(RDD_BADARG, rdd_recv_info(reader, &filename, &file_size, &block_size, 0, &ewf, &flags));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));

	return 1;	
}

static int
test_rdd_recv_info_ewf_null()
{
	RDD_READER * reader;
	char * filename;
	rdd_count_t file_size;
	rdd_count_t block_size;
	rdd_count_t split_size;
	unsigned int flags;

	// user file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info", 0));

	CHECK_UINT(RDD_BADARG, rdd_recv_info(reader, &filename, &file_size, &block_size, &split_size, 0, &flags));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));

	return 1;	
}

static int
test_rdd_recv_info_flags_null()
{
	RDD_READER * reader;
	char * filename;
	rdd_count_t file_size;
	rdd_count_t block_size;
	rdd_count_t split_size;
	int ewf;

	// user file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info", 0));

	CHECK_UINT(RDD_BADARG, rdd_recv_info(reader, &filename, &file_size, &block_size, &split_size, &ewf, 0));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));

	return 1;	
}

static int
test_rdd_recv_info()
{
	RDD_READER * reader;
	char * filename;
	rdd_count_t file_size;
	rdd_count_t block_size;
	rdd_count_t split_size;
	int ewf;
	unsigned int flags;

	// user file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info", 0));

	CHECK_UINT(RDD_OK, rdd_recv_info(reader, &filename, &file_size, &block_size, &split_size, &ewf, &flags));

	CHECK_STRING("filename_to_send", filename);
	CHECK_UINT(0x38, file_size);
	CHECK_UINT(0x78, block_size);
	CHECK_UINT(0x289, split_size);
	CHECK_UINT(0x1, ewf);
	CHECK_UINT(0x938, flags);
	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));

	return 1;	
}

static int
test_rdd_recv_info_filename_len_too_long()
{
	RDD_READER * reader;
	char * filename;
	rdd_count_t file_size;
	rdd_count_t block_size;
	rdd_count_t split_size;
	int ewf;
	unsigned int flags;

	// user file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info_filename_len_too_long", 0));

	CHECK_UINT(RDD_ERANGE, rdd_recv_info(reader, &filename, &file_size, &block_size, &split_size, &ewf, &flags));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));
	return 1;	
}

static int
test_rdd_recv_info_filename_len_0()
{
	RDD_READER * reader;
	char * filename;
	rdd_count_t file_size;
	rdd_count_t block_size;
	rdd_count_t split_size;
	int ewf;
	unsigned int flags;

	// user file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info_filename_len_0", 0));

	CHECK_UINT(RDD_ESYNTAX, rdd_recv_info(reader, &filename, &file_size, &block_size, &split_size, &ewf, &flags));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));
	return 1;	
}

static int
test_rdd_recv_info_empty_filename()
{
	RDD_READER * reader;
	char * filename;
	rdd_count_t file_size;
	rdd_count_t block_size;
	rdd_count_t split_size;
	int ewf;
	unsigned int flags;

	// user file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info_empty_filename", 0));

	CHECK_UINT(RDD_OK, rdd_recv_info(reader, &filename, &file_size, &block_size, &split_size, &ewf, &flags));

	CHECK_STRING("", filename);
	CHECK_UINT(0x38, file_size);
	CHECK_UINT(0x78, block_size);
	CHECK_UINT(0x289, split_size);
	CHECK_UINT(0x1, ewf);
	CHECK_UINT(0x938, flags);
	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));
	return 1;	
}

static int
test_rdd_recv_info_filename_not_terminated()
{
	RDD_READER * reader;
	char * filename;
	rdd_count_t file_size;
	rdd_count_t block_size;
	rdd_count_t split_size;
	int ewf;
	unsigned int flags;

	// user file reader to test
	CHECK_UINT(RDD_OK, rdd_open_file_reader(&reader, "netio_info_filename_not_terminated", 0));

	CHECK_UINT(RDD_ESYNTAX, rdd_recv_info(reader, &filename, &file_size, &block_size, &split_size, &ewf, &flags));

	CHECK_UINT(RDD_OK, rdd_reader_close(reader, 1));
	return 1;	
}

static int
test_init_server_printer_null()
{
	int socket;
	CHECK_UINT(RDD_BADARG, rdd_init_server(0, 0, &socket));
	CHECK_INT(-1, socket);
	return 1;
}

static int
test_init_server_socket_null()
{
	RDD_MSGPRINTER * printer;

	CHECK_UINT(RDD_OK, rdd_mp_open_file_printer(&printer, "netio_msgprinter_output", 1));
	CHECK_NOT_NULL(printer);
		
	CHECK_UINT(RDD_BADARG, rdd_init_server(printer, 0, 0));

	CHECK_UINT(RDD_OK, rdd_mp_close(printer, 0));
	return 1;
}

static int
test_init_server_port_toolarge()
{
	RDD_MSGPRINTER * printer;
	int socket;

	CHECK_UINT(RDD_OK, rdd_mp_open_file_printer(&printer, "netio_msgprinter_output", 1));
	CHECK_NOT_NULL(printer);
		
	CHECK_UINT(RDD_OK, rdd_init_server(printer, 0xffffffff, &socket));

	CHECK_UINT(RDD_OK, rdd_mp_close(printer, 0));
	
	CHECK_INT(1, (socket!=-1));	

	return 1;
}

static int
test_init_server_port_0()
{
	RDD_MSGPRINTER * printer;
	int socket;

	CHECK_UINT(RDD_OK, rdd_mp_open_file_printer(&printer, "netio_msgprinter_output", 1));
	CHECK_NOT_NULL(printer);
		
	CHECK_UINT(RDD_OK, rdd_init_server(printer, 0x0, &socket));

	CHECK_UINT(RDD_OK, rdd_mp_close(printer, 0));

	CHECK_INT(1, (socket!=-1));
	return 1;
}

static int
test_init_server_port()
{
	RDD_MSGPRINTER * printer;
	int socket;

	CHECK_UINT(RDD_OK, rdd_mp_open_file_printer(&printer, "netio_msgprinter_output", 1));
	CHECK_NOT_NULL(printer);
		
	CHECK_UINT(RDD_OK, rdd_init_server(printer, 10000, &socket));

	CHECK_UINT(RDD_OK, rdd_mp_close(printer, 0));

	CHECK_INT(1, (socket!=-1));
	return 1;
}

static int
test_init_server_port_permission_denied()
{
	RDD_MSGPRINTER * printer;
	int socket;

	CHECK_UINT(RDD_OK, rdd_mp_open_file_printer(&printer, "netio_msgprinter_output", 1));
	CHECK_NOT_NULL(printer);
		
	CHECK_UINT(RDD_EOPEN, rdd_init_server(printer, 0x1, &socket));

	CHECK_UINT(RDD_OK, rdd_mp_close(printer, 0));

	CHECK_INT(-1, socket);
	return 1;
}

static int
test_await_connection_printer_null()
{
	int client_socket;
	CHECK_UINT(RDD_BADARG, rdd_await_connection(0, 0, &client_socket));
	CHECK_INT(-1, client_socket);
	return 1;
}

static int
test_await_connection_client_socket_null()
{
	RDD_MSGPRINTER * printer;

	CHECK_UINT(RDD_OK, rdd_mp_open_file_printer(&printer, "netio_msgprinter_output", 1));
	CHECK_NOT_NULL(printer);

	CHECK_UINT(RDD_BADARG, rdd_await_connection(printer, 0, 0));

	CHECK_UINT(RDD_OK, rdd_mp_close(printer, 0));
	return 1;
}

static int
test_await_connection_server_not_initialised()
{
	RDD_MSGPRINTER * printer;
	int client_socket;

	CHECK_UINT(RDD_OK, rdd_mp_open_file_printer(&printer, "netio_msgprinter_output", 1));
	CHECK_NOT_NULL(printer);

	CHECK_UINT(RDD_EOPEN, rdd_await_connection(printer, 10000, &client_socket));
	CHECK_INT(-1, client_socket);

	CHECK_UINT(RDD_OK, rdd_mp_close(printer, 0));
	return 1;
}


static int
call_tests(void)
{
	int result = 1;

	TEST(test_pack_netnum_packed_null);
	TEST(test_pack_netnum_0);
	TEST(test_pack_netnum);
	TEST(test_pack_netnum_large);

	TEST(test_unpack_netnum_packed_null);
	TEST(test_unpack_netnum_num_null);
	TEST(test_unpack_netnum_0);
	TEST(test_unpack_netnum);
	TEST(test_unpack_netnum_large);

	TEST(test_rdd_send_info_writer_null);
	TEST(test_rdd_send_info_filename_null);
	TEST(test_rdd_send_info_filename_too_large);
	TEST(test_rdd_send_info);

	TEST(test_receive_reader_null);
	TEST(test_receive_buffer_null);
	TEST(test_receive);
	TEST(test_receive_read_less_bytes);
	TEST(test_receive_too_many_bytes);

	TEST(test_rdd_recv_info_reader_null);
	TEST(test_rdd_recv_info_filename_null);
	TEST(test_rdd_recv_info_file_size_null);
	TEST(test_rdd_recv_info_block_size_null);
	TEST(test_rdd_recv_info_split_size_null);
	TEST(test_rdd_recv_info_ewf_null);
	TEST(test_rdd_recv_info_flags_null);
	TEST(test_rdd_recv_info);
	TEST(test_rdd_recv_info_filename_len_too_long);
	TEST(test_rdd_recv_info_filename_len_0);
	TEST(test_rdd_recv_info_empty_filename);
	TEST(test_rdd_recv_info_filename_not_terminated);

	TEST(test_init_server_printer_null);
	TEST(test_init_server_socket_null);
	TEST(test_init_server_port_toolarge);
	TEST(test_init_server_port_0);
	TEST(test_init_server_port);
	TEST(test_init_server_port_permission_denied);

	TEST(test_await_connection_printer_null);
	TEST(test_await_connection_client_socket_null);
	TEST(test_await_connection_server_not_initialised);
	// currently not testing a regular call for test_await_connection; need multiple threads
	return result;
}

TEST_MAIN;
