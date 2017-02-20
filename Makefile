PREFIX := /usr/local

all: tests

clean:
	@$(MAKE) --no-print-directory -C tests clean

tests:
	@$(MAKE) --no-print-directory -C tests

install:
	@echo Installing headers to $(PREFIX)/include
	@mkdir -p $(PREFIX)/include
	@cp -r include/liblinux $(PREFIX)/include

uninstall:
	@echo Uninstalling headers from $(PREFIX)/include
	@rm -rf $(PREFIX)/include/liblinux

.PHONY: all clean tests install uninstall
