# Development prerequisites only: tools/codex/versions.env and the canonical
# setup script remain the single language/tool dependency authority.
FROM mcr.microsoft.com/playwright@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e

COPY ubuntu-snapshot.list /etc/apt/linura-snapshot.list
RUN apt-get -o APT::Update::Error-Mode=any \
       -o Dir::Etc::sourcelist=/etc/apt/linura-snapshot.list \
       -o Dir::Etc::sourceparts=- update \
    && DEBIAN_FRONTEND=noninteractive apt-get \
       -o Dir::Etc::sourcelist=/etc/apt/linura-snapshot.list \
       -o Dir::Etc::sourceparts=- install -y --no-install-recommends \
       build-essential cmake ninja-build pkg-config \
       qt6-base-dev qt6-declarative-dev python3-venv python3-dev \
       qemu-system-x86 qemu-utils openssh-client cloud-image-utils \
       ffmpeg imagemagick ca-certificates \
    && dpkg-query -W -f='${binary:Package}\t${Version}\n' > /opt/linura-development-packages.tsv \
    && echo '4eb4d71ec34b49a3dd94e19a831376feb40d1a7311af305f354e4da9ebee85a5  /opt/linura-development-packages.tsv' | sha256sum --check --strict \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete

RUN mkdir -p /workspace /build && chown 1000:1000 /workspace /build
LABEL org.linura.role="development-build-only" org.linura.qualification-evidence="false"
ENV HOME=/home/ubuntu LANG=C.UTF-8 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/build/linura-target
USER 1000:1000
WORKDIR /workspace
CMD ["sleep", "infinity"]
