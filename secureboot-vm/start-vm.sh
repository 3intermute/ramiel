#!/bin/bash

#         -net nic,model=virtio -net user,hostfwd=tcp::${SSH_PORT}-:22 \

set -Eeuxo pipefail

LOG="debug.log"
MACHINE_NAME="disk"
QEMU_IMG="${MACHINE_NAME}.img"
SSH_PORT="5555"
OVMF_CODE_SECURE="ovmf/OVMF_CODE_SECURE.fd"
OVMF_CODE="ovmf/OVMF_CODE.fd"
OVMF_VARS_ORIG="/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
OVMF_VARS_SECURE="ovmf/OVMF_VARS_4M_SECURE.ms.fd"
# re-compile and then copy and generate gdbscript, then dont regenerate gdbscript for OVMF non secure boot
OVMF_VARS="ovmf/OVMF_VARS.fd"

if [ ! -e "${QEMU_IMG}" ]; then
        qemu-img create -f qcow2 "${QEMU_IMG}" 8G
fi

if [ ! -e "${OVMF_VARS}" ]; then
        cp "${OVMF_VARS_ORIG}" "${OVMF_VARS}"
fi

qemu-system-x86_64 \
        -enable-kvm \
        -cpu host -smp cores=4,threads=1 -m 2048 \
        -object rng-random,filename=/dev/urandom,id=rng0 \
        -device virtio-rng-pci,rng=rng0 \
        -name "${MACHINE_NAME}" \
        -drive file="${QEMU_IMG}",format=qcow2 \
        -vga virtio \
        -machine q35,smm=on \
        -global driver=cfi.pflash01,property=secure,value=on \
        -drive format=raw,file=fat:rw:fs1 \
        -drive if=pflash,format=raw,unit=0,file="${OVMF_CODE_SECURE}",readonly=on \
        -drive if=pflash,format=raw,unit=1,file="${OVMF_VARS_SECURE}" \
        -debugcon file:"${LOG}" -global isa-debugcon.iobase=0x402 \
        -global ICH9-LPC.disable_s3=1 \
        -serial file:com1.log \
        -device e1000e,romfile=chainloader.efirom \
        $@
