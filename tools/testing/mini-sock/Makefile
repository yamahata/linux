# SPDX-License-Identifier: GPL-2.0-or-later
#
# sample test program for mini sock device
#
# Copyright (c) 2023 Intel Corporation
#
# Author:
#  Isaku Yamahata <isaku.yamahata@gmail.com>
#

CFLAGS += -ggdb3 -Wall -MMD -D_GNU_SOURCE

PROGS = \
	test

.PHONY: all
all: $(PROGS)

.PHONY: clean
clean:
	$(RM) *.o
	$(RM) $(PROGS)

-include *.d
