#!/bin/sh

. "$PROJECT_DIR/scripts/core.sh"

CC=gcc

rm -rf ${OBJDIR};
mkdir -p ${LIB_DIR};
mkdir -p ${BIN_DIR};

for DIR in $SUB_DIRS; do
        build_subdir ${DIR} 1 || exit $?;
done
build_asm

OBJECTS=$(collect_objects)

COMMAND="${CC} ${LDFLAGS} -o ${TEST_LIB_NAME} ${OBJECTS}";
if [ "$SILENT" != "1" ]; then
	echo ${COMMAND};
fi
${COMMAND} || exit $?;

if [ "${ARCH}" = "aarch64" ]; then
	CFLAGS="${CFLAGS} -mno-outline-atomics";
fi

COMMAND="${CC} -DCOVERAGE ${CDEFS} -fno-builtin -lc -lgcc --coverage -I${INCDIR} -o ${TEST_BIN} ${TEST_SRC} ${OBJECTS}";

if [ "$SILENT" != "1" ]; then
	echo ${COMMAND};
fi
${COMMAND} || exit $?;

export TEST_PATTERN="*";
LD_LIBRARY_PATH=${LIB_DIR} ${TEST_BIN} || { echo "tests failed!"; exit 1; }

for DIR in ${SUB_DIRS}; do
    src_dir="./src/${DIR}"
    dst_dir="./target/cov/objs/${DIR}"

    if [ -d "$src_dir" ] && ls "$src_dir"/*.c >/dev/null 2>&1; then
        cp "$src_dir"/*.c "$dst_dir"/
        touch "$dst_dir"/*
    fi
done

LINESUM=0;
COVEREDSUM=0;
echo "------------------------------------------------------------------------------------------";

cd ./target/cov/objs

for DIR in *; do
    # Skip if not a directory (in case of files in objs/)
    [ -d "$DIR" ] || continue
    cd "$DIR" || continue

    for FILE in *.c; do
        [ -f "$FILE" ] || continue
        case "$FILE" in
            "./test.c" | "test.c") continue ;;
        esac
	PERCENT=`gcov ${FILE} 2> /dev/null \
            | grep "^Lines" | head -1 | cut -f2 -d ' ' \
            | cut -f2 -d ':' | cut -f1 -d '%' | tr -d \\n`;

        if [ "${PERCENT}" = "" ]; then
            PERCENT=0.00;
        fi;
	LINES=`gcov ${FILE} 2> /dev/null | grep "^Lines" \
                                | head -1 | cut -f4 -d ' ' | tr -d \\n`;
                        if [ "${LINES}" = "" ]; then
                                LINES=0;
                                PERCENT=100.00;
                        fi
	BASENAME=$(basename "${FILE}")
        RATIO=`awk "BEGIN {print $PERCENT / 100}"`;
        COVERED=`awk "BEGIN {print int($RATIO * $LINES)}"`;
        LINESUM=`awk "BEGIN {print $LINESUM + $LINES}"`;
        COVEREDSUM=`awk "BEGIN {print ${COVEREDSUM} + ${COVERED}}"`;
	printf "${GREEN}%-28s${RESET} %6s%% - ${YELLOW}[%3s/%3s]${RESET}\n" \
            "${DIR}/${BASENAME}" \
            "${PERCENT}" \
            "${COVERED}" \
            "${LINES}"
    done
    cd ..;
done

cd ../../..

echo "------------------------------------------------------------------------------------------";

CODECOV=`awk "BEGIN {printf \"%.2f\", 100 * ${COVEREDSUM} / ${LINESUM}}"`
echo "Coverage: ${CODECOV}% [${COVEREDSUM} / ${LINESUM}]";

TIMESTAMP=`date +%s`
echo "$CODECOV" > /tmp/cc_final;
echo "$TIMESTAMP $CODECOV $COVEREDSUM $LINESUM" > /tmp/cc.txt
chmod 777 /tmp/cc_final /tmp/cc.txt

