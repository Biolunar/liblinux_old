#
# Copyright 2017 Mahdi Khanalizadeh
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

CC       := clang
CFLAGS   := -std=c11 -pedantic-errors -g -I../include
WARNINGS := -Weverything -Wno-c99-compat -Wno-switch-enum -Wno-c++98-compat -Wno-c++-compat
LIBS     := -llinux_syscall -pthread

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
