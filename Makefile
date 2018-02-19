#
# Copyright 2018 Mahdi Khanalizadeh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

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
