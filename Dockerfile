FROM ubuntu as build

# Requires
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -qqy update
RUN apt-get -qqy install git gcc g++ make libssl-dev zlib1g-dev wget cmake ninja-build

# Code
COPY . /src

# Build project
RUN mkdir -p /src/build
WORKDIR /src/build
RUN cmake \
 -DCMAKE_BUILD_TYPE=Release \
 -DBUILD_TESTING=OFF \
 -DTON_USE_ROCKSDB=OFF \
 -DTON_USE_ABSEIL=OFF \
 -DTON_USE_GDB=OFF \
 -DTON_USE_STACKTRACE=OFF \
 -G Ninja \
 ..
RUN ninja -j$(nproc)
RUN /src/build/bin/ton-msig --version

# Reliase
FROM ubuntu
RUN apt-get -qqy update &&\
    apt-get -qqy install openssl &&\
    apt-get clean
COPY --from=build /src/build/bin/ton-msig /usr/bin/ton-msig
ENTRYPOINT ["ton-msig"]
CMD ["--help"]
