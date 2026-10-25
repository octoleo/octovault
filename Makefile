SHELL := /bin/bash
VERSION := $(shell cat VERSION)
PREFIX ?= /usr
DESTDIR ?=
CC ?= cc
PKG_CONFIG ?= pkg-config
CPPFLAGS += -DOCTOVAULT_VERSION=\"$(VERSION)\" -Isrc/service
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wformat=2 -Werror=format-security -fstack-protector-strong
LDFLAGS += -Wl,-z,relro,-z,now
CORE_PKGS := gio-2.0 gio-unix-2.0 json-glib-1.0
GUI_PKGS := $(CORE_PKGS) gtk4 libadwaita-1
CORE_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(CORE_PKGS))
CORE_LIBS := $(shell $(PKG_CONFIG) --libs $(CORE_PKGS))
GUI_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(GUI_PKGS))
GUI_LIBS := $(shell $(PKG_CONFIG) --libs $(GUI_PKGS))

.PHONY: all gui check test lint install clean package
all: build/octovault build/octovaultd build/octovault-session build/pinentry-octovault build/steghide gui
gui: build/octovault-gtk

build:
	mkdir -p $@

build/octovaultd: src/service/daemon.c src/service/access.c src/service/access-store.c src/service/access-recovery.c src/service/client.c src/service/client.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CORE_CFLAGS) src/service/daemon.c src/service/client.c -o $@ $(LDFLAGS) $(CORE_LIBS)

build/octovault: src/service/cli.c src/service/client.c src/service/client.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CORE_CFLAGS) src/service/cli.c src/service/client.c -o $@ $(LDFLAGS) $(CORE_LIBS)

build/octovault-gtk: src/ui/main.c src/ui/file-picker.c src/ui/backup-setup.c src/service/client.c src/service/client.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(GUI_CFLAGS) src/ui/main.c src/service/client.c -o $@ $(LDFLAGS) $(GUI_LIBS)

build/octovault-session: src/session/main.c src/service/client.c src/service/client.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CORE_CFLAGS) src/session/main.c src/service/client.c -o $@ $(LDFLAGS) $(CORE_LIBS)

build/pinentry-octovault: src/service/pinentry.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS)

build/steghide: src/service/steghide.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS) -lutil

lint:
	@while IFS= read -r -d '' source; do bash -n "$$source" || exit; done < <(find lib scripts tests -type f -name '*.sh' -print0)
	@for source in lib/octovault/backend lib/octovault/run-plan lib/octovault/event-system lib/octovault/priority-backend; do bash -n "$$source" || exit; done
	@shellcheck --severity=warning lib/octovault/*.sh lib/octovault/backend lib/octovault/run-plan lib/octovault/event-system lib/octovault/priority-backend scripts/*.sh tests/test-*.sh
	@desktop-file-validate data/io.vdm.OctoVault.desktop data/io.vdm.OctoVault.Session.desktop
	@xmllint --noout data/io.vdm.OctoVault.metainfo.xml data/io.vdm.octovault.policy data/io.vdm.OctoVault1.conf
	@bash scripts/version.sh --check

test:
	@set -e; for test in tests/test-*.sh; do test -f "$$test" || continue; printf 'Running %s\n' "$$test"; bash "$$test"; done
	@bash scripts/test-packaging.sh

check: all lint test

install: all
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/libexec/octovault $(DESTDIR)$(PREFIX)/lib/octovault
	install -m 0755 build/octovault build/octovault-gtk build/octovault-session build/pinentry-octovault $(DESTDIR)$(PREFIX)/bin/
	install -m 0755 build/octovaultd $(DESTDIR)$(PREFIX)/libexec/octovault/daemon
	install -m 0755 build/steghide $(DESTDIR)$(PREFIX)/libexec/octovault/steghide
	install -m 0755 lib/octovault/backend $(DESTDIR)$(PREFIX)/libexec/octovault/backend
	install -m 0755 lib/octovault/run-plan lib/octovault/event-system lib/octovault/priority-backend $(DESTDIR)$(PREFIX)/libexec/octovault/
	install -m 0644 lib/octovault/*.sh $(DESTDIR)$(PREFIX)/lib/octovault/
	install -d $(DESTDIR)$(PREFIX)/share/octovault/cloak-ciphers
	install -m 0644 data/cloak-ciphers/words $(DESTDIR)$(PREFIX)/share/octovault/cloak-ciphers/
	install -d $(DESTDIR)$(PREFIX)/share/applications $(DESTDIR)$(PREFIX)/share/metainfo
	install -m 0644 data/io.vdm.OctoVault.desktop $(DESTDIR)$(PREFIX)/share/applications/
	install -m 0644 data/io.vdm.OctoVault.metainfo.xml $(DESTDIR)$(PREFIX)/share/metainfo/
	install -d $(DESTDIR)/etc/xdg/autostart
	install -m 0644 data/io.vdm.OctoVault.Session.desktop $(DESTDIR)/etc/xdg/autostart/
	install -d $(DESTDIR)$(PREFIX)/share/polkit-1/actions $(DESTDIR)$(PREFIX)/share/dbus-1/system-services $(DESTDIR)$(PREFIX)/share/dbus-1/system.d
	install -m 0644 data/io.vdm.octovault.policy $(DESTDIR)$(PREFIX)/share/polkit-1/actions/
	install -m 0644 data/io.vdm.OctoVault1.service $(DESTDIR)$(PREFIX)/share/dbus-1/system-services/
	install -m 0644 data/io.vdm.OctoVault1.conf $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/
	install -d $(DESTDIR)$(PREFIX)/lib/systemd/system $(DESTDIR)$(PREFIX)/lib/systemd/user
	install -m 0644 systemd/octovault.service $(DESTDIR)$(PREFIX)/lib/systemd/system/
	install -m 0644 systemd/octovault-sleep.service systemd/octovault-shutdown.service $(DESTDIR)$(PREFIX)/lib/systemd/system/
	@for operation in suspend hibernate hybrid-sleep suspend-then-hibernate; do install -d "$(DESTDIR)$(PREFIX)/lib/systemd/system/systemd-$$operation.service.d"; install -m 0644 systemd/sleep-dependency.conf "$(DESTDIR)$(PREFIX)/lib/systemd/system/systemd-$$operation.service.d/10-octovault.conf"; done
	install -d $(DESTDIR)$(PREFIX)/lib/systemd/system/shutdown.target.wants
	ln -sfn ../octovault-shutdown.service $(DESTDIR)$(PREFIX)/lib/systemd/system/shutdown.target.wants/octovault-shutdown.service
	install -m 0644 systemd/octovault-session.service $(DESTDIR)$(PREFIX)/lib/systemd/user/
	install -d $(DESTDIR)$(PREFIX)/share/icons/hicolor/512x512/apps $(DESTDIR)$(PREFIX)/share/icons/hicolor/symbolic/apps
	install -m 0644 data/icons/hicolor/512x512/apps/io.vdm.OctoVault.png $(DESTDIR)$(PREFIX)/share/icons/hicolor/512x512/apps/
	install -m 0644 data/icons/hicolor/symbolic/apps/io.vdm.OctoVault-symbolic.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/symbolic/apps/
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 0644 docs/octovault.1 $(DESTDIR)$(PREFIX)/share/man/man1/

package:
	dpkg-buildpackage -us -uc -b

clean:
	rm -rf build
