PREFIX := /usr/local

all: lib

clean:
	@$(MAKE) --no-print-directory -C src clean
	@$(MAKE) --no-print-directory -C tests clean

lib:
	@$(MAKE) --no-print-directory -C src

tests: lib
	@$(MAKE) --no-print-directory -C tests

install: all
	@echo Installing headers to $(PREFIX)/include
	@mkdir -p $(PREFIX)/include
	@cp -r include/liblinux $(PREFIX)/include
	@echo Installing library to $(PREFIX)/lib
	@mkdir -p $(PREFIX)/lib
	@cp -r src/liblinux.a $(PREFIX)/lib

uninstall:
	@echo Uninstalling headers from $(PREFIX)/include
	@rm -rf $(PREFIX)/include/liblinux
	@echo Uninstalling library from $(PREFIX)/lib
	@rm -rf $(PREFIX)/lib/liblinux.a

.PHONY: all clean lib tests install uninstall
