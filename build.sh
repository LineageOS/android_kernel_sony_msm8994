#!/bin/bash
export KERNELDIR=~/choose/kernel/sony/msm8994
cd $KERNELDIR
export ANYKERNEL=$KERNELDIR/AnyKernel2
make clean && make mrproper
TOOLCHAINDIR=~/choose/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/
export ARCH=arm64
export KBUILD_BUILD_USER="x0r3d"
export KBUILD_BUILD_HOST="L1nux1sX0R1N6"
export CC=~/choose/prebuilts/clang/linux-x86/host/sdclang-3.8/bin/clang
export CXX=~/choose/prebuilts/clang/linux-x86/host/sdclang-3.8/bin/clang++
export CLANG_TRIPLE=aarch64-linux-gnu-
export CROSS_COMPILE=$TOOLCHAINDIR/bin/aarch64-linux-android-
export USE_CCACHE=1
export CCACHE_DIR=../.ccache
export FINALZIP=kernel.zip

make clean && make mrproper
make kitakami_sumire_defconfig
make -j$( nproc --all )

cp arch/arm64/boot/Image.gz-dtb $ANYKERNEL
cd $ANYKERNEL
zip -r kernel.zip *