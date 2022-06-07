import "hash" 

rule MATCHMD5 {

    meta:
        description = "MD5 IoCs"

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        hash.md5(0, filesize) == "e30299799c4ece3b53f4a7b8897a35b6"   or  
        hash.md5(0, filesize) == "897a35b6e30299799c4ece3b53f4a7b8"   or 
        hash.md5(0, filesize) == "6462c8c3b51e302997897a35ba7b8846"   or 
        hash.md5(0, filesize) == "e30f4a7b8897219799c4ece3b4ece377"   or 
        hash.md5(0, filesize) == "9c4ece3b53f4a7b8897e3063379a35b6"   or  
        hash.md5(0, filesize) == "a45f7fcc14b9b6462c8c3b51623c4301"     
}
