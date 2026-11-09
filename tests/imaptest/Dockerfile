# Dovecot imaptest (IMAP compliance and stress tester) against a running beavermaild.
# Dovecot is installed only for libdovecot, which imaptest links to; no Dovecot service runs.
FROM archlinux:latest

RUN pacman -Syu --noconfirm --needed base-devel git dovecot && pacman -Scc --noconfirm

# Last imaptest commit before it moved to post-2.4 Dovecot APIs (Arch ships Dovecot 2.4).
ARG IMAPTEST_REF=ec2e118671a64ce47b552ad11c57fecde279445b
RUN git clone https://github.com/dovecot/imaptest.git /imaptest \
	&& cd /imaptest \
	&& git checkout "$IMAPTEST_REF" \
	&& ./autogen.sh \
	&& ./configure --with-dovecot=/usr/lib/dovecot \
		LDFLAGS="-L/usr/lib/dovecot/modules -Wl,-rpath,/usr/lib/dovecot/modules" \
	&& make -j"$(nproc)" -C src imaptest

WORKDIR /imaptest
ENTRYPOINT ["/imaptest/src/imaptest"]
