FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get install -y \
    git \
    curl \
    build-essential \
    autoconf \
    m4 \
    softhsm2 \
    locales \
    && locale-gen en_US.UTF-8 \
    && update-locale LANG=en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

ENV ASDF_VERSION=v0.18.0 \
    LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

# Install asdf
RUN ASDF_ARCH="$(dpkg --print-architecture)" && \
    case "$ASDF_ARCH" in \
      amd64) ASDF_ARCH="amd64" ;; \
      arm64) ASDF_ARCH="arm64" ;; \
      *) echo "Unsupported architecture: $ASDF_ARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/asdf.tar.gz \
    "https://github.com/asdf-vm/asdf/releases/download/${ASDF_VERSION}/asdf-${ASDF_VERSION}-linux-${ASDF_ARCH}.tar.gz" && \
    tar -xzf /tmp/asdf.tar.gz -C /usr/local/bin asdf && \
    rm /tmp/asdf.tar.gz
ENV PATH="/root/.asdf/shims:/usr/local/bin:$PATH"

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
    && rm -rf /var/lib/apt/lists/*

ENV PKCS11SPY=/usr/lib/softhsm/libsofthsm2.so 
# ENV PKCS11SPY_OUTPUT=/tmp/pkcs11spy.log

# Install Erlang
RUN asdf plugin add erlang && \
    asdf install erlang 27.3 && \
    asdf install erlang 28.3 && \
    echo "erlang 27.3" >> $HOME/.tool-versions

# Install Elixir
RUN asdf plugin add elixir && \
    asdf install elixir 1.18.4-otp-27 && \
    asdf install elixir 1.18.4-otp-28 && \
    asdf install elixir 1.19.5-otp-27 && \
    asdf install elixir 1.19.5-otp-28 && \
    echo "elixir 1.19.5-otp-27" >> $HOME/.tool-versions

WORKDIR /app 

CMD ["/bin/bash"]
