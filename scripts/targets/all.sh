#!/bin/sh

. "$PROJECT_DIR/scripts/core.sh"

mkdir -p ${LIB_DIR};
mkdir -p ${BIN_DIR};

for DIR in $SUB_DIRS; do
        build_subdir ${DIR} 0 || exit $?;
done
build_asm

OBJECTS=$(collect_objects)

if needs_rebuild "$LIB_NAME" $OBJECTS; then
        if [ "${OBJECTS}" != "" ]; then
                COMMAND="${CC} ${LDFLAGS} -o ${LIB_NAME} ${OBJECTS}";
                if [ "$SILENT" != "1" ]; then
                        echo ${COMMAND};
                fi
                ${COMMAND} || exit $?;
        fi
fi


COMMAND="${CC} \
-o ${BIN_DIR}/stormvec \
${STORMVEC_SRC} \
-I${INCDIR} \
-nostdlib \
-ffreestanding \
-L${LIB_DIR} \
-lfam"

#if [ ! -e "${BIN_DIR}/stormvec" ] || [ "${STORMVEC_SRC}" -nt "${BIN_DIR}/stormvec" ]; then
#	if [ "$SILENT" != "1" ]; then
#		echo ${COMMAND};
#        fi
#	${COMMAND} || exit 1;
#fi

COMMAND="${CC} \
-o ${BIN_DIR}/czip \
${CZIP_SRC} \
-I${INCDIR} \
-nostdlib \
-ffreestanding \
-L${LIB_DIR} \
-lfam"

#if [ ! -e "${BIN_DIR}/czip" ] || [ "${CZIP_SRC}" -nt "${BIN_DIR}/czip" ]; then
#        if [ "$SILENT" != "1" ]; then
#                echo ${COMMAND};
#        fi
#        ${COMMAND} || exit 1;
#fi

