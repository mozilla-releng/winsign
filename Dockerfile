FROM debian:buster

RUN apt-get update
RUN apt-get upgrade

# Install pyenv
RUN apt-get install -y git
RUN apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev \
libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
xz-utils tk-dev libffi-dev liblzma-dev python-openssl
RUN git clone git://github.com/yyuu/pyenv.git /root/.pyenv
ENV PYENV_ROOT /root/.pyenv
ENV PATH $PYENV_ROOT/shims:$PYENV_ROOT/bin:$PATH
RUN pyenv install 3.8-dev
RUN pyenv install 3.7.3
RUN pyenv install 3.6.8

RUN apt-get install -y osslsigncode tox

WORKDIR /src
