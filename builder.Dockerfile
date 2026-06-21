# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG parent_image
FROM $parent_image

ARG AFLPP_COMMIT=56d5aa3101945e81519a3fac8783d0d8fad82779

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        python3-dev \
        python3-setuptools \
        automake \
        cmake \
        git \
        flex \
        libomp-dev \
        bison \
        libglib2.0-dev \
        libpixman-1-dev \
        cargo \
        libgtk-3-dev \
        # for QEMU mode
        ninja-build \
        gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
        libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

# Подготовка кастомного мутатора
RUN mkdir -p /out/custom_mutators
COPY . /workspace

# Download afl++.
RUN git clone  https://github.com/AFLplusplus/AFLplusplus /afl && \
    cd /afl && \
    git checkout "${AFLPP_COMMIT}" && \
    test "$(git rev-parse HEAD)" = "${AFLPP_COMMIT}"




# Build without Python support as we don't need it.
# Set AFL_NO_X86 to skip flaky tests.
RUN cd /afl && unset CFLAGS CXXFLAGS && export CC=clang AFL_NO_X86=1 && \
    PYTHON_INCLUDE=/ make && \
    cp utils/aflpp_driver/libAFLDriver.a /

RUN cd /workspace && \
    make AFL_INCLUDE=/afl/include && \
    cp ca_mutator_xor.so ca_mutator_growing.so /out/custom_mutators/
