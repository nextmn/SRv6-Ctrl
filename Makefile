prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
BASHCOMPLETIONSDIR = $(exec_prefix)/share/bash-completion/completions


RM = rm -f
INSTALL = install -D
MKDIRP = mkdir -p

.PHONY: install uninstall update build clean default
default: build
build:
	go build
clean:
	go clean
reinstall: uninstall install
install:
	$(INSTALL) srv6-ctrl $(DESTDIR)$(bindir)/srv6-ctrl
	$(MKDIRP) $(DESTDIR)$(BASHCOMPLETIONSDIR)
	$(DESTDIR)$(bindir)/srv6-ctrl completion bash > $(DESTDIR)$(BASHCOMPLETIONSDIR)/srv6-ctrl
	@echo "================================="
	@echo ">> Now run the following command:"
	@echo "\tsource $(DESTDIR)$(BASHCOMPLETIONSDIR)/srv6-ctrl"
	@echo "================================="
uninstall:
	$(RM) $(DESTDIR)$(bindir)/srv6-ctrl
	$(RM) $(DESTDIR)$(BASHCOMPLETIONSDIR)/srv6-ctrl
