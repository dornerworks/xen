XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror
CFLAGS += $(CFLAGS_libxenctrl)
LDLIBS += $(LDLIBS_libxenctrl)
LDLIBS += $(ARGP_LDFLAGS)

BIN      = a653_sched

.PHONY: all
all: build

.PHONY: build
build: $(BIN)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(bindir)
ifneq ($(BIN),)
	$(INSTALL_PROG) $(BIN) $(DESTDIR)$(bindir)
endif

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(BIN) $(DEPS)

.PHONY: distclean
distclean: clean

a653_sched: a653_sched.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS) $(APPEND_LDFLAGS)

-include $(DEPS)