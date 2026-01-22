# scripts/core.sh
# Loaded by every target – contains ALL real build logic

. "$PROJECT_DIR/scripts/config.sh"

# Generators
. "$PROJECT_DIR/scripts/xxdir.sh"

TAG=$(git describe --tags --dirty 2>/dev/null || echo "2.0.0")
printf '#define LIBFAM_VERSION "%s"\n' "$TAG" > "$PROJECT_DIR/src/include/libfam/version.h"

SUB_DIRS="base crypto core"
INCDIR="src/include"
LIB_DIR="${OUTDIR}/lib"
LIB_NAME="${LIB_DIR}/libfam.so";
TEST_LIB_NAME="${LIB_DIR}/libfamtest.so";
BIN_DIR="${OUTDIR}/bin";
TEST_BIN="${BIN_DIR}/runtests";
TEST_SRC="src/test/main.c";

if [ "$NO_COLOR" = "" ]; then
   GREEN="\033[32m";
   CYAN="\033[36m";
   YELLOW="\033[33m";
   BRIGHT_RED="\033[91m";
   RESET="\033[0m";
   BLUE="\033[34m";
else
   GREEN="";
   CYAN="";
   YELLOW="";
   BRIGHT_RED="";
   RESET="";
   BLUE="";
fi

build_asm() {
    local objdir="$OBJDIR/asm"
    mkdir -p "$objdir"

    if [ "${ARCH}" = "x86_64" ]; then
        local srcdir="$PROJECT_DIR/src/asmx64"
        for src in "$srcdir"/*.S; do
            [ -f "$src" ] || continue
            basename="${src##*/}"

            obj="$objdir/${basename%.S}.o"

            if [ ! -f "$obj" ] || [ "$src" -nt "$obj" ]; then
                COMMAND="$CC $CDEFS $MARCH_EXTRA -I$PROJECT_DIR/$INCDIR -c $src -o $obj";
                [ "$SILENT" != "1" ] && echo ${COMMAND};
                ${COMMAND} || exit $?;
            fi
        done
    else
	 local srcdir="$PROJECT_DIR/src/asmarm64"
         for src in "$srcdir"/*.S; do
            [ -f "$src" ] || continue
            basename="${src##*/}"

            obj="$objdir/${basename%.S}.o"

            if [ ! -f "$obj" ] || [ "$src" -nt "$obj" ]; then
                COMMAND="$CC $CDEFS $MARCH_EXTRA -march=armv8-a+crypto -I$PROJECT_DIR/$INCDIR -c $src -o $obj";
                [ "$SILENT" != "1" ] && echo ${COMMAND};
                ${COMMAND} || exit $?;
            fi
        done
    fi
}

build_subdir() {
    local subdir="$1"
    local allow_test_c="$2"

    local srcdir="$PROJECT_DIR/src/$subdir"
    local objdir="$OBJDIR/$subdir" 

    mkdir -p "$objdir"

    for src in "$srcdir"/*.c; do
        [ -f "$src" ] || continue
        basename="${src##*/}"
        [ "$basename" = "test.c" ] && [ "$allow_test_c" = "0" ] && continue

        obj="$objdir/${basename%.c}.o"

        if [ ! -f "$obj" ] || [ "$src" -nt "$obj" ]; then
            COMMAND="$CC -I$PROJECT_DIR/$INCDIR $CFLAGS $CDEFS -c $src -o $obj";
            [ "$SILENT" != "1" ] && echo ${COMMAND};
	    ${COMMAND} || exit $?;
        fi
    done
}

collect_objects() {
    find "$OBJDIR" -name '*.o' 2>/dev/null | tr '\n' ' '
}

needs_rebuild() {
    local target="$1"; shift
    [ ! -f "$target" ] && return 0
    for obj in "$@"; do
        [ "$obj" -nt "$target" ] && return 0
    done
    return 1
}

