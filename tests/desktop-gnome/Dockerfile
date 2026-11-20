# syntax=docker/dockerfile:1.7-labs
# Build context: tests/desktop-gnome. No application or browser is downloaded here.
# Official Ubuntu 24.04 multi-platform digest, resolved 2026-11-20.
ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8
FROM ${UBUNTU_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      gnome-shell gnome-session-bin gnome-settings-daemon gnome-backgrounds \
      gsettings-desktop-schemas adwaita-icon-theme \
      dbus dbus-x11 dbus-user-session accountsservice upower \
      xvfb xauth x11-utils x11-xserver-utils xdotool scrot \
      libgl1-mesa-dri libglx-mesa0 mesa-utils \
      libgbm1 libasound2t64 libnss3 libnspr4 libatk-bridge2.0-0t64 \
      libgtk-3-0t64 libxss1 libx11-xcb1 libxtst6 \
      xdg-utils desktop-file-utils libnotify-bin pinentry-gnome3 \
      python3 python3-gi gir1.2-glib-2.0 curl ca-certificates \
      procps util-linux tini socat \
    && useradd --create-home --uid 1100 --shell /bin/bash desktop \
    && rmdir /run/systemd/seats \
    && install -d -o desktop -g desktop /home/desktop/.cache \
    && install -d -m 0700 -o desktop -g desktop /run/user/1100 \
    && install -d -o desktop -g desktop /home/desktop/.cache/desktop-gnome \
       /home/desktop/.local/share/applications /home/desktop/.config \
    && install -d /opt/desktop-gnome
COPY entrypoint.sh session.sh desktop.sh browser.sh probe.py /opt/desktop-gnome/
RUN chmod 0755 /opt/desktop-gnome/*.sh /opt/desktop-gnome/probe.py \
    && printf '%s\n' '[Desktop Entry]' 'Type=Application' \
       'Name=Disposable test browser' 'Exec=/opt/desktop-gnome/browser.sh %U' \
       'Terminal=false' 'NoDisplay=true' \
       'MimeType=text/html;x-scheme-handler/http;x-scheme-handler/https;' \
       > /usr/share/applications/desktop-gnome-browser.desktop \
    && update-desktop-database /usr/share/applications
ENV HOME=/home/desktop USER=desktop LOGNAME=desktop \
    DISPLAY=:99 XDG_RUNTIME_DIR=/run/user/1100 \
    XDG_CONFIG_HOME=/home/desktop/.config \
    XDG_DATA_HOME=/home/desktop/.local/share \
    XDG_CACHE_HOME=/home/desktop/.cache \
    XDG_CURRENT_DESKTOP=GNOME XDG_SESSION_DESKTOP=gnome XDG_SESSION_TYPE=x11 \
    GNOME_SHELL_SESSION_MODE=user GSETTINGS_BACKEND=dconf \
    LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe \
    GNOME_TEST_BROWSER=/opt/browser/chrome GNOME_TEST_VIRTUAL_CAMERA=0
# Root is used only to start the container-private system bus and drop privileges.
# Shell, X server, browser, and application all run as uid 1100.
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/opt/desktop-gnome/entrypoint.sh"]
