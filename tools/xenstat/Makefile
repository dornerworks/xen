XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS :=
SUBDIRS += libxenstat

# This doesn't cross-compile (cross-compile environments rarely have curses)
SUBDIRS += xentop

.PHONY: all install clean distclean

all install clean distclean: %: subdirs-%
