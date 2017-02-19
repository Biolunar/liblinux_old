CC       := clang
CFLAGS   := -std=c11 -pedantic-errors -I../include -L../src/build
WARNINGS := -Weverything -Wno-c99-compat -Wno-switch-enum
LIBS     := -llinux -llinux_syscall

BUILDDIR := build
SOURCES  := $(sort $(wildcard *.c))
TARGETS  := $(patsubst %.c, $(BUILDDIR)/%, $(SOURCES))

all: $(TARGETS)
	@$(foreach prog,$^,$(prog);)

$(TARGETS): $(BUILDDIR)/%: %.c | $(BUILDDIR)
	@$(CC) $(CFLAGS) $(WARNINGS) $< $(LIBS) -o $@

$(BUILDDIR):
	@mkdir $@

clean:
	@rm -rf $(BUILDDIR)

.PHONY: all clean
