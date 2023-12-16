// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include "ipc.h"
#include "server.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

#define OPEN_C(file) \
	open(file, O_RDWR|O_CREAT|O_APPEND, 0600)
#define OPEN_R(file) \
	open(file, O_RDONLY)

int shell_open_ca(file, mode) {
	// if (mode == IO_REGULAR)
		return open(file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	// else if (mode == IO_OUT_APPEND) {
		// return open(file, O_RDWR|O_CREAT|O_APPEND, 0600);
	// }
	// return open(file, O_RDWR|O_CREAT|O_APPEND, 0600);
}

#define OPEN_CA(file, mode) shell_open_ca(file, mode)

static char *output_name(int seed) {
	int seed_digit = seed % 10;
	char *out = strdup(OUTPUT_TEMPLATE);
	int h = 0;
	seed += rand() % 27103;

	for (int i = 0; i < strlen(OUTPUT_TEMPLATE); ++i) {
		if (OUTPUT_TEMPLATE[i] == 'X')
			h ++;
		if (OUTPUT_TEMPLATE[i] == 'X' && seed_digit > 0) {
			out[i] = '0' + seed_digit;
			seed /= 10;
			seed_digit = seed % 10;
		} else if (OUTPUT_TEMPLATE[i] == 'X') {
			out[i] = 'A' + h;
		}
	} 
	return out;
}

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */
	return 0;
}

static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */
	char *file_out = output_name(42);
	lib->outputfile = file_out;
	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	lib->handle = dlopen(lib->libname, RTLD_NOW|RTLD_GLOBAL);
	int BACKUPS_FILENO[] = {
		dup(STDIN_FILENO),
		dup(STDOUT_FILENO),
		dup(STDERR_FILENO)
	};
	int REDIRECTS_FILENO[] = {-1,-1,-1};

	char *outfile = lib->outputfile;
	int ofd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	// printf("OUT FILE DESC: %d\n", ofd);
	REDIRECTS_FILENO[1] = dup2(ofd, STDOUT_FILENO);

	
	if(strlen(lib->filename) == 0) {
		// printf("lib_execute: [%s] of [%s]\n", lib->funcname, lib->libname);
		lambda_func_t run;
		// printf("single param \n");
		if(strlen(lib->funcname) != 0)
			run = (lambda_func_t)dlsym(lib->handle, lib->funcname);
		else 
			run = (lambda_func_t)dlsym(lib->handle, "run");
		char *error;
		if ((error = dlerror()) != NULL)  {
			// printf("error: %s\n", error);
			return -1;
		}

		lib->run = run;
		lib->run();
	} else {
		// printf("m_lib_execute: [%s] of [%s], [%s]\n", lib->funcname, lib->libname, lib->filename);
		lambda_param_func_t run;
		// printf("multiple param\n");
		run = (lambda_param_func_t)dlsym(lib->handle, lib->funcname);
		char *error;
		if ((error = dlerror()) != NULL)  {
			// printf("error: %s\n", error);
			return -1;
		}

		lib->p_run = run;
		lib->p_run(lib->filename);
	}
	fflush(stdout);
	for (int i = 0; i < 3; ++i)
		if (REDIRECTS_FILENO[i] != -1)
			close(REDIRECTS_FILENO[i]);
	for (int i = 0; i < 3; ++i)
		if (REDIRECTS_FILENO[i] != -1)
			dup2(BACKUPS_FILENO[i], i);

	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	return dlclose(lib->handle);
}


static int lib_posthooks(struct lib *lib)
{
	/* TODO: Implement lib_posthooks(). */
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	/* TODO: Implement server connection. */
	int ret;
	struct lib lib;

	// lib_prehooks(lib);
	srand(time(NULL));   // Initialization, should only be called once.

	
	remove(SOCKET_NAME);
	int fd = create_socket();
	bind_socket(fd);
	listen_socket(fd);
	
	while (1) {
		char buf[BUFSIZE];
		char name[BUFSIZE]; 
		char func[BUFSIZE];
		char params[BUFSIZE];
		/* TODO - get message from client */
		memset(buf, 0, BUFSIZE-1);
		memset(name, 0, BUFSIZE-1);
		memset(func, 0, BUFSIZE-1);
		memset(params, 0, BUFSIZE-1);
		int new_descriptor = accept_socket(fd);
		
		recv_socket(new_descriptor, buf, BUFSIZE);
		/* TODO - parse message with parse_command and populate lib */
		int ret = parse_command(buf, name, func, params);
		if(ret == -1) {
			break;
		}
		lib.libname = strdup(name);
		lib.funcname = strdup(func);
		lib.filename = strdup(params);
		// printf("%s %s %s: begining\n", lib.libname, lib.funcname, lib.filename);
		// afli adresa functiei (nmap)
		// in parralel https://www.geeksforgeeks.org/handling-multiple-clients-on-server-with-multithreading-using-socket-programming-in-c-cpp/
		// https://gist.github.com/tailriver/30bf0c943325330b7b6a
		// offsetezi, mmap, rulezi https://stackoverflow.com/questions/12409908/invoking-a-function-main-from-a-binary-file-in-c
		/* TODO - handle request from client */
		ret = lib_run(&lib);
		send_socket(new_descriptor, lib.outputfile, strlen(lib.outputfile));

		// printf("retvalue: %d\n", ret);
		
		close_socket(new_descriptor);
		free(lib.libname);
		free(lib.funcname);
		free(lib.filename);
	}

	// lib_posthooks(lib);

	return 0;
}
