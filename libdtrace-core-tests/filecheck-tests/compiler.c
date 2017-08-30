#include <sys/dtrace.h>

#include <errno.h>
#include <dtrace.h>
#include <dt_impl.h>
#include <dt_printf.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc, const char *argv[])
{
	dtrace_hdl_t *g_dtp;
	dtrace_prog_t *prog;
	int err;
	FILE *fp;

	if (argc <= 1) {
		fprintf(stdout, "Supply a path\n");
		return (0);
	}

	g_dtp = dtrace_open(DTRACE_VERSION, 0, &err);

	if (g_dtp == NULL) {
		fprintf(stderr, "Failed to open DTrace device\n");
		return (1);
	}

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open file: %s\n", argv[1]);
		return (1);
	}

	prog = dtrace_program_fcompile(g_dtp, fp, DTRACE_C_DIFV, 0, NULL);
	if (prog == NULL) {
		fprintf(stderr, "Failed to compile script\n");
		return (1);
	}

	fclose(fp);

	if (g_dtp)
		dtrace_close(g_dtp);
	return (0);
}
