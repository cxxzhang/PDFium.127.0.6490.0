#!/bin/bash -e

# Copyright 2024 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Script to install build dependencies of packages which we instrument.

# TODO(eugenis): find a way to pull the list from the build config.
packages="\
alsa-lib \
at-spi2-core \
avahi \
brltty \
cairo \
cups \
curl \
cyrus-sasl2 \
dbus \
dbus-glib \
dee \
dpkg \
expat \
fontconfig \
freetype \
gdk-pixbuf \
git \
glib2.0 \
gnome-common \
gnome-keyring \
gobject-introspection \
graphite2 \
gtk+3.0 \
gyp \
ido \
jasper-initramfs \
libappindicator \
libcap2 \
libdbusmenu \
libffi \
libgpg-error \
libidn \
libindicator \
libjpeg-turbo \
libmicrohttpd \
liboss4-salsa-asound2 \
libpng1.6 \
libunity \
libx11 \
libxau \
libxcb \
libxcomposite \
libxcursor \
libxdamage \
libxdmcp \
libxext \
libxfixes \
libxi \
libxinerama \
libxkbcommon \
libxrandr \
libxrender \
libxss \
libxtst \
nspr \
nss \
opensc \
openssl \
p11-kit \
pango1.0 \
pciutils \
pcre3 \
pixman \
pkgconf \
pulseaudio \
rtmpdump \
wayland \
zlib"

sudo apt-get build-dep -y $packages
