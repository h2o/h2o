/*
 * Public domain
 *
 * Dongsheng Song <dongsheng.song@gmail.com>
 * Brent Cook <bcook@openbsd.org>
 */

#include <windows.h>

#include <io.h>
#include <fcntl.h>

#include "apps.h"

double
app_tminterval(int stop, int usertime)
{
	static unsigned __int64 tmstart;
	union {
		unsigned __int64 u64;
		FILETIME ft;
	} ct, et, kt, ut;

	GetProcessTimes(GetCurrentProcess(), &ct.ft, &et.ft, &kt.ft, &ut.ft);

	if (stop == TM_START) {
		tmstart = ut.u64 + kt.u64;
	} else {
		return (ut.u64 + kt.u64 - tmstart) / (double) 10000000;
	}
	return 0;
}

int
setup_ui(void)
{
	ui_method = UI_create_method("OpenSSL application user interface");
	UI_method_set_opener(ui_method, ui_open);
	UI_method_set_reader(ui_method, ui_read);
	UI_method_set_writer(ui_method, ui_write);
	UI_method_set_closer(ui_method, ui_close);

	/*
	 * Set STDIO to binary
	 */
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
	_setmode(_fileno(stderr), _O_BINARY);

	return 0;
}

void
destroy_ui(void)
{
	if (ui_method) {
		UI_destroy_method(ui_method);
		ui_method = NULL;
	}
}
