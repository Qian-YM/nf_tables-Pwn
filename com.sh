gcc -fno-stack-protector -o test netlink.c exp.c --static -masm=intel
cp ./rootfs.cpio.bak  ./rootfs.cpio
echo test | cpio -o --format=newc >> ./rootfs.cpio
echo flag | cpio -o --format=newc >> ./rootfs.cpio
