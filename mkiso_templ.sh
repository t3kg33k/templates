#!/bin/bash
# confirm older file removed from home directory
rm -f $HOME/youriso.iso
# change to the iso directory where DVD contents exist
cd $HOME/iso_build
# make the iso
sudo mkisofs -o $HOME/youriso_r2.iso -b isolinux/isolinux.bin -c isolinux/boot.cat --no-emul-boot --boot-load-size 4 --boot-info-table -J -R -V disks .
