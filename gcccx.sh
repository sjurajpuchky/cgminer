#!/bin/bash

#ISICC=`echo $PATH|grep intel`

#if [ -z "$ISICC" ]; then
export PATH="$PATH:/usr/local/cuda/bin"
#fi
export CUDA_HOME="/usr/local/cuda"
export CUDAHOME="/usr/local/cuda"
export LD=gcc
export CCLD=gcc
export AR=ar
export CCAR=ar
export CC="gcc"
export HOSTCC="gcc"
export CXX="g++"
export CPP="gcc -E"
export CXXCPP="g++ -E"
export SHLIB_CXXLD="gcc"
export SHLIB_CCLD="gcc"
#export OPT="-Os -ipo -parallel -fast -openmp -axSSE2"

export OPT="-O3 -mtune=nocona -fopenmp -ftree-parallelize-loops=2 -pthread"
export CFLAGS="$OPT -I/usr/local/cuda/include -I/usr/local/cuda-5.5/include/CL -I/usr/include" 
export CXXFLAGS="$OPT -I/usr/local/cuda/include -I/usr/local/cuda-5.5/include/CL -I/usr/include" 
export CPPFLAGS=" $OPT -I/usr/local/cuda/include -I/usr/local/cuda-5.5/include/CL" 
export LDFLAGS="-L/usr/local/cuda/lib64 -L/usr/lib64 -lgomp"
export CXXLDFLAGS="-L/usr/local/cuda/lib64 -L/usr/lib64"
export CPPLDFLAGS="-L/usr/local/cuda/lib64 -L/usr/lib64"
#/opt/intel/bin/iccvars.sh intel64
#/opt/intel/bin/compilervars.sh intel64
./configure $1 LIBCURL_LIBS="/usr/lib64/libcurl.so" --libdir=/usr/lib64 --enable-npumining --enable-mpumining --enable-cudadrive --enable-cpumining --enable-cldrive --prefix=/usr 
