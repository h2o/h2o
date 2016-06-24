/*
 * Copyright (c) 2016 Fastly, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "gkc.h"

void print_query(struct gkc_summary *s, double q)
{
	double v = gkc_query(s, q);
	fprintf(stderr, "queried: %.02f, found: %.02f\n", q, v);
}

int main(void)
{
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
	unsigned int i;
#if 0
	double input[] = {
		3658, 3673, 3693, 3715, 3723, 3724, 3724, 3690, 3695, 3689, 3695, 3700,
		3690, 3699, 3699, 3701, 3704, 3704, 3714, 3707, 3698, 3701, 3697, 3697,
		3712, 3713, 3714, 3715, 3717, 3712, 3712, 3717, 3728, 3728, 3744, 3751,
		3764, 3751, 3798, 3802, 3800, 3824, 3810, 3824, 3811, 3802, 3811, 3801,
		3791, 3796, 3803, 3817, 3819, 3818, 3815, 3804, 3796, 3784, 3783, 3784,
		3774, 3776, 3776, 3764, 3763, 3806, 3819, 3835, 3825, 3786, 3795, 3795,
		3776, 3760, 3789, 3786, 3771, 3778, 3782, 3776, 3781, 3784, 3801, 3810,
		3815, 3792, 3764, 3770, 3746, 3741, 3746, 3756, 3755, 3775, 3776, 3773,
		3777, 3801, 3804, 3807
	};
#else
	double input[] = { 12, 6, 10, 1 };
#endif
	FILE *out;
	struct gkc_summary *summary;
	struct gkc_summary *s1, *s2, *snew;

	summary = gkc_summary_alloc(0.01);
	print_query(summary, 0.1);
	goto test_combine;
	summary = gkc_summary_alloc(0.01);

#if 0
	for (i = 0; i < ARRAY_SIZE(input); i++) {
		gkc_insert_value(&summary, input[i]);
	}
	gkc_print_summary(&summary);
	print_query(&summary, 0);
	print_query(&summary, .25);
	print_query(&summary, .5);
	print_query(&summary, .75);
	print_query(&summary, 1);
	return 0;
#else
	(void)input;
#endif

#define tofile 0
	if (tofile) {
		out = fopen("data", "w+");
	}
	srandom(time(NULL));
	for (i = 0; i < 10 * 1000 * 1000; i++) {
		long r = random() % 10000;
		gkc_insert_value(summary, r);
		if (tofile) {
			fprintf(out, "%ld\n", r);
		}
	}
	if (tofile) {
		fclose(out);
	}
	gkc_print_summary(summary);
	print_query(summary, .02);
	print_query(summary, .1);
	print_query(summary, .25);
	print_query(summary, .5);
	print_query(summary, .75);
	print_query(summary, .82);
	print_query(summary, .88);
	print_query(summary, .86);
	print_query(summary, .99);

	gkc_sanity_check(summary);

	gkc_summary_free(summary);

test_combine:
	s1 = gkc_summary_alloc(0.01);
	s2 = gkc_summary_alloc(0.01);

	for (i = 0; i < 1 * 10 * 1000; i++) {
		long r = random() % 10000;
		gkc_insert_value(s1, r);
	}
#if 0
	for (i = 0; i < 1 * 1 * 1000; i++) {
		gkc_insert_value(s2, 111);
	}
#endif
	snew = gkc_combine(s1, s2);
	gkc_summary_free(s1);
	gkc_summary_free(s2);

	gkc_print_summary(snew);
	print_query(snew, .02);
	print_query(snew, .1);
	print_query(snew, .25);
	print_query(snew, .5);
	print_query(snew, .75);
	print_query(snew, .82);
	print_query(snew, .88);
	print_query(snew, .86);
	print_query(snew, .99);

	gkc_sanity_check(snew);

	gkc_summary_free(snew);

	return 0;
}
