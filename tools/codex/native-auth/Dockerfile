# Development/build dependencies only. This image runs no authentication daemon,
# compositor, executor, VM, or qualification producer.
FROM docker.io/library/buildpack-deps@sha256:af40ae792b5ee49c4fd176078d6947ee1ba44f92daebf1b4db79d482b9bd7c12 AS native-auth-dependencies

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# Official noble-curl base supplies its digest-bound TLS trust store. All new
# packages come only from the signed snapshot; no trust checks are disabled.
COPY ubuntu-snapshot.list /etc/apt/linura-snapshot.list
COPY packages.txt /opt/linura-native-auth/packages.txt
RUN test "$(dpkg --print-architecture)" = amd64 \
    && apt-get -o APT::Update::Error-Mode=any -o Dir::Etc::sourcelist=/etc/apt/linura-snapshot.list -o Dir::Etc::sourceparts=- update \
    && xargs -r apt-get -o Dir::Etc::sourcelist=/etc/apt/linura-snapshot.list -o Dir::Etc::sourceparts=- install -y --no-install-recommends < /opt/linura-native-auth/packages.txt \
    && dpkg-query -W -f='${binary:Package}\t${Version}\n' > /opt/linura-native-auth/installed-packages.tsv \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete

FROM native-auth-dependencies
COPY contract.json check.py /opt/linura-native-auth/
LABEL org.linura.role="development-build-only" org.linura.qualification-evidence="false"
WORKDIR /build
USER 1000:1000
RUN --network=none python3 /opt/linura-native-auth/check.py --json
CMD ["sleep", "infinity"]
