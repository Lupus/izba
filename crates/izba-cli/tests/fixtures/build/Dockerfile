# Minimal fixture for the build-in-VM e2e: a base pull + a RUN layer that writes
# a marker the test reads back. The marker is created root-owned 0644 (world
# readable), then we drop to a non-root USER so the built image follows
# least-privilege (and satisfies the Dockerfile root-user lint, docker:S6471).
FROM alpine:3.20
RUN echo izba-build-ok > /izba-build-marker
USER nobody
