FROM gcr.io/fuzzbench/base-image
ENV LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/out"
ENV CA_MUTATOR_VARIANT=xor
ENV AFL_CUSTOM_MUTATOR_LIBRARY=/out/custom_mutators/ca_mutator_xor.so

#ENV AFL_MAP_SIZE=2621440
ENV PATH="$PATH:/out"
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV AFL_TESTCACHE_SIZE=2
# RUN apt-get update && apt-get upgrade && apt install -y unzip git gdb joe
