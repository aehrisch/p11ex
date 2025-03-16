FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y \
    git \
    curl \
    build-essential \
    autoconf \
    m4 \
    softhsm2 \
    locales \
    && locale-gen en_US.UTF-8 \
    && update-locale LANG=en_US.UTF-8

ENV ASDF_VERSION=v0.16.2 \
    LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

# Install asdf
RUN git clone https://github.com/asdf-vm/asdf.git ~/.asdf --branch ${ASDF_VERSION}
ENV PATH="/root/.asdf/shims:/root/.asdf/bin:$PATH"

RUN echo '. "$HOME/.asdf/asdf.sh"' >> ~/.bashrc && \
    echo '. "$HOME/.asdf/completions/asdf.bash"' >> ~/.bashrc

# Install Erlang and Elixir
RUN apt-get install -y \
    autoconf \
    m4 \
    libncurses5-dev \
    libwxgtk3.2-dev \
    libwxgtk-webview3.2-dev \
    libgl1-mesa-dev \
    libglu1-mesa-dev \
    libpng-dev \
    libssh-dev \
    unixodbc-dev \
    xsltproc \
    fop \
    libxml2-utils \
    libncurses-dev \
    openjdk-11-jdk \
    opensc \
    opensc-pkcs11 \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu

ENV PKCS11SPY=/usr/lib/softhsm/libsofthsm2.so 
# ENV PKCS11SPY_OUTPUT=/tmp/pkcs11spy.log

# Install Erlang
RUN asdf plugin add erlang && \
    asdf install erlang 27.2 && \
    asdf global erlang 27.2 && \
    erl -version && \
    echo "erlang 27.2" >> $HOME/.tool-versions

# Install Elixir
RUN asdf plugin add elixir && \
    asdf install elixir 1.17.3 && \
    asdf global elixir 1.17.3 && \
    elixir -v && \
    echo "elixir 1.17.3" >> $HOME/.tool-versions

WORKDIR /app 

CMD ["/bin/bash"]
