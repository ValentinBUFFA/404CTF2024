```
> file image.img  
image.img: DOS/MBR boot sector

> mmls image.img  
GUID Partition Table (EFI)  
Offset Sector: 0  
Units are in 512-byte sectors  
  
     Slot      Start        End          Length       Description  
000:  Meta      0000000000   0000000000   0000000001   Safety Table  
001:  -------   0000000000   0000002047   0000002048   Unallocated  
002:  Meta      0000000001   0000000001   0000000001   GPT Header  
003:  Meta      0000000002   0000000033   0000000032   Partition Table  
004:  000       0000002048   0000018431   0000016384      
005:  001       0000018432   0011552767   0011534336      
006:  002       0011552768   0012582878   0001030111      
007:  -------   0012582879   0012582911   0000000033   Unallocated

> sudo losetup -fP image.img
> sudo mount /dev/loop0p2 mnt
> xfsrestore -f mnt/var/backup/home_backup.xfsdump home_restored
```