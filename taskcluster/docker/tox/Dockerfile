FROM debian:bullseye

VOLUME /builds/worker/checkouts

# Add worker user
RUN mkdir -p /builds && \
    groupadd -g 1000 worker && \
    useradd -u 1000 -g 1000 -d /builds/worker -s /bin/bash -m worker && \
    mkdir /builds/worker/artifacts && \
    chown worker:worker /builds/worker /builds/worker/artifacts

RUN apt-get update && \
    apt-get install -y osslsigncode git python3 python3-distutils

# %ARG UV_VERSION
COPY --from=ghcr.io/astral-sh/uv:$UV_VERSION /uv /uvx /usr/local/bin/

RUN uv tool install tox --with tox-uv

USER worker

# %ARG PYTHON_VERSIONS
RUN uv python install $PYTHON_VERSIONS

USER root

# %include-run-task

ENV SHELL=/bin/sh \
    HOME=/builds/worker \
    PATH=/builds/worker/.local/bin:$PATH

# Set a default command useful for debugging
CMD ["/bin/bash"]
