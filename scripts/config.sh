# scripts/config.sh
# This file is sourced by core.sh – it defines EVERY flag and path based on BUILD_MODE

# ------------------------------------------------------------------
# 1. Determine build mode and set output directories
# ------------------------------------------------------------------
case "${BUILD_MODE:-all}" in
    all)
        OUTDIR="target"
        OBJDIR="target/objs"
        ;;
    test)
        OUTDIR="target"
        OBJDIR="target/test/objs"
        ;;
    bench)
	OUTDIR="target"
	OBJDIR="target/bench/objs"
	;;
    cov)
        OUTDIR="target/cov"
        OBJDIR="target/cov/objs"
        ;;
    clean|install)
        OUTDIR="target"
        OBJDIR="target/objs"
        ;;
    *)
        echo "Error: Unknown BUILD_MODE='$BUILD_MODE'" >&2
        exit 1
        ;;
esac

# Export so core.sh and targets can use them
export OUTDIR OBJDIR
export LIBDIR="$OUTDIR/lib"
export BINDIR="$OUTDIR/bin"
export STORMVEC_SRC="etc/stormvec.c";
export CZIP_SRC="etc/czip.c";

# ------------------------------------------------------------------
# 2. Base compiler and linker settings (common to all modes)
# ------------------------------------------------------------------
CC="${CC:-clang}"

if [ "${BASE_CFLAGS}" = "" ]; then
	PAGE_SIZE=$(getconf PAGE_SIZE 2>/dev/null)

	if [ "${BUILD_MODE}" = "cov" ]; then
		BASE_CFLAGS="-DPAGE_SIZE=${PAGE_SIZE} -Werror -Wall -funroll-loops -fstack-protector-strong -std=c11"
	else
		BASE_CFLAGS="-DPAGE_SIZE=${PAGE_SIZE} -Werror -Wall -funroll-loops -fstack-protector-strong -std=c11 -O3"
	fi
fi
BASE_LDFLAGS="-shared -fstack-protector-strong -ffreestanding -nostdlib -Wl,--no-eh-frame-hdr"

# ------------------------------------------------------------------
# 3. Mode-specific flags
# ------------------------------------------------------------------
case "$BUILD_MODE" in
    all)
        CFLAGS="$BASE_CFLAGS"
        LDFLAGS="$BASE_LDFLAGS"
        VISIBILITY="-fvisibility=hidden"
        CDEFS="-DSTATIC=static -DTEST=0"
        COVERAGE=""
        LTO="-flto=auto"
        ;;
    test|cov)
        CFLAGS="$BASE_CFLAGS"
        LDFLAGS="$BASE_LDFLAGS"
        VISIBILITY=""
	if [ "${VALGRIND}" = "1" ]; then
		CDEFS="-DTEST=1 -DSTATIC= -DNO_VECTOR"
	else
        	CDEFS="-DTEST=1 -DSTATIC="
	fi
        COVERAGE=""
        [ "$BUILD_MODE" = "cov" ] && COVERAGE="--coverage -DCOVERAGE" && LDFLAGS="$LDFLAGS"
        LTO=""
        ;;
    bench)
        CFLAGS="$BASE_CFLAGS"
        LDFLAGS="$BASE_LDFLAGS"
        VISIBILITY=""
        CDEFS="-DSTATIC= -DTEST=1"
        COVERAGE=""
        [ "$BUILD_MODE" = "cov" ] && COVERAGE="--coverage -DCOVERAGE" && LDFLAGS="$LDFLAGS"
        LTO=""
        ;;
    *)
        # clean/install – minimal flags (won't be used anyway)
        CFLAGS="$BASE_CFLAGS"
        LDFLAGS="$BASE_LDFLAGS"
        VISIBILITY="-fvisibility=hidden"
        CDEFS="-DSTATIC=static -DTEST=0"
        COVERAGE=""
        LTO="-flto=auto"
        ;;
esac

# ------------------------------------------------------------------
# 4. Architecture-specific flags
# ------------------------------------------------------------------
ARCH=$(uname -m);
case "${ARCH}" in
    x86_64)
        MARCH="haswell"
	mkdir -p ${BINDIR}
	${CC} etc/mvaes.c -o ${BINDIR}/mvaes
	${BINDIR}/mvaes
	if [ "$?" = "1" ]; then
            MARCH_EXTRA="-maes"
	else
            MARCH_EXTRA="-mvaes"
	fi
        ;;
    aarch64)
        MARCH="armv8-a+crypto"
        MARCH_EXTRA="-mno-outline-atomics"
        ;;
    *)
        MARCH="native"
        MARCH_EXTRA=""
        ;;
esac

# ------------------------------------------------------------------
# 5. Global user overrides and quirks
# ------------------------------------------------------------------
[ "$NO_LTO" = "1" ] && LTO=""
[ "$MEM_TRACKING" = "1" ] && CDEFS="$CDEFS -DMEM_TRACKING"

# Clang vs GCC quirks
case "$CC" in
    *clang*) COMPILER_FIXES="-fno-builtin" ;;
    *gcc*|*g++) COMPILER_FIXES="-fno-builtin" ;;
    *) COMPILER_FIXES="" ;;
esac

# ------------------------------------------------------------------
# 6. Final exported variables
# ------------------------------------------------------------------
export CFLAGS="$CFLAGS \
    -fno-pie -fPIC \
    $VISIBILITY $LTO \
    -march=$MARCH $MARCH_EXTRA \
    $COMPILER_FIXES $COVERAGE \
    $EXTRA_CFLAGS"

export LDFLAGS="$LDFLAGS \
    $VISIBILITY $LTO \
    $COVERAGE \
    $EXTRA_LDFLAGS"

export CDEFS

# For debugging – uncomment if you ever need to see what’s being used
# echo "BUILD_MODE=$BUILD_MODE  CC=$CC  CFLAGS=$CFLAGS" >&2
