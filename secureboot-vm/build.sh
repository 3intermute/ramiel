cd ../edk2 && \
source edksetup.sh && \
cd ../secureboot-vm && \
build -p ../edk2/MdeModulePkg/MdeModulePkg.dsc -b DEBUG -a X64 -t GCC5 && \
../edk2/BaseTools/Source/C/bin/EfiRom -f 0x8086 -i 0x10d3 -v --debug 9 -o chainloader.efirom -e ../edk2/Build/MdeModule/DEBUG_GCC5/X64/chainloader.efi && \
cd gdbscript_ && \
./gen_symbol_offsets.sh > gdbscript_MdeModule_offsets && \
cd ..
cp ../edk2/Build/MdeModule/DEBUG_GCC5/X64/helloworld_driver.efi ../runtime/
