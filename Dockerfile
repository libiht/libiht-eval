FROM --platform=linux/amd64 ubuntu:24.04


# Install eval dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    cmake \
    gcc g++ gdb \
    git \
    gnupg gnupg2 \
    openssh-client \
    python3-dev \
    python3-pip \
    python-is-python3 \
    wget && \
    apt-get clean && apt-get autoremove && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install Pin to tools directory and add to PATH
RUN mkdir -p /tools/pin && \
    curl -L https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz | tar -xz -C /tools/pin --strip-components=1 && \
    echo "export PIN_ROOT=/tools/pin" >> ~/.bashrc && \
    echo "export PATH=\$PIN_ROOT:\$PATH" >> ~/.bashrc

# Install DynamoRIO to tools directory and add to PATH
RUN mkdir -p /tools/dynamorio && \
    curl -L https://github.com/DynamoRIO/dynamorio/releases/download/release_11.3.0-1/DynamoRIO-Linux-11.3.0.tar.gz | tar -xz -C /tools/dynamorio --strip-components=1 && \
    echo "export DYNAMORIO_HOME=/tools/dynamorio" >> ~/.bashrc && \
    echo "export PATH=\$DYNAMORIO_HOME/bin64:\$PATH" >> ~/.bashrc

# TODO: Install Intel SDE?
# https://downloadmirror.intel.com/843185/sde-external-9.48.0-2024-11-25-lin.tar.xz

# TODO: Install Valgrind?
# https://sourceware.org/pub/valgrind/valgrind-3.24.0.tar.bz2

# TODO: Dependencies for coreutils

