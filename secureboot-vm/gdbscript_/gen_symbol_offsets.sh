#!/bin/bash

LOG="../debug.log"
# searchpath mdemodule /home/null/Desktop/projects/ramiel/edk2/Build/MdeModule/DEBUG_GCC5/X64
# searchpath ovmf /home/null/Desktop/projects/ramiel/edk2/Build/OvmfX64/DEBUG_GCC5/X64
PEINFO="peinfo/peinfo"

cat ${LOG} | grep Loading | grep -i efi | while read LINE; do
  BASE="`echo ${LINE} | cut -d " " -f4`"
  NAME="`echo ${LINE} | cut -d " " -f6 | tr -d "[:cntrl:]"`"
  EFIFILE="`find /home/null/Desktop/projects/ramiel/edk2/Build/MdeModule/DEBUG_GCC5/X64 -name ${NAME} -maxdepth 1 -type f`"
  if [ -z "$EFIFILE" ]
  then
      :
  else
      ADDR="`${PEINFO} ${EFIFILE} \
            | grep -A 5 text | grep VirtualAddress | cut -d " " -f2`"
      TEXT="`python -c "print(hex(${BASE} + ${ADDR}))"`"
      SYMS="`echo ${NAME} | sed -e "s/\.efi/\.debug/g"`"
      SYMFILE="`find /home/null/Desktop/projects/ramiel/edk2/Build/MdeModule/DEBUG_GCC5/X64 -name ${SYMS} -maxdepth 1 -type f`"
      echo "add-symbol-file ${SYMFILE} ${TEXT}"
  fi
done
