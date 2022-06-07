rule webshell_jsp_converge : Webshell
{
    meta:
        author = "threatintel@volexity.com"
        description = "File upload webshell observed in incident involving compromise of Confluence server."
        date = "2022-06-01"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        
    strings:
        $s1 = "if (request.getParameter(\"name\")!=null && request.getParameter(\"name\").length()!=0){" ascii

    condition:
        $s1
}

rule general_jsp_possible_tiny_fileuploader : General Webshells
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects small .jsp files which have possible file upload utility."
        date = "2022-06-01"
        hash1 = "4addb9bc9e5e1af8fda63589f6b3fc038ccfd651230fa3fa61814ad080e95a12"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        
    strings:
        // read a req parameter of some sort
        $required1 = "request." ascii
        // write a file
        $required2 = "java.io.FileOutputStream" ascii
        $required3 = ".write" ascii

        // do some form of decoding.
        $encoding1 = "java.util.Base64" ascii
        $encoding2 = "crypto.Cipher" ascii
        $encoding3 = ".misc.BASE64Decoder" ascii

    condition:
        (
            filesize < 4KB and
            all of ($required*) and
            any of ($encoding*)
        )
        or
        (
            filesize < 600 and
            all of ($required*)
        )
}

rule webshell_java_realcmd : Commodity Webshells
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the RealCMD webshell, one of the payloads for BEHINDER."
        date = "2022-06-01"
        hash1 = "a9a30455d6f3a0a8cd0274ae954aa41674b6fd52877fafc84a9cb833fd8858f6"
        reference = "https://github.com/Freakboy/Behinder/blob/master/src/main/java/vip/youwe/sheller/payload/java/RealCMD.java"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        
    strings:
        $fn1 = "runCmd" wide ascii fullword
        $fn2 = "RealCMD" ascii wide fullword
        $fn3 = "buildJson" ascii wide fullword
        $fn4 = "Encrypt" ascii wide fullword

        $s1 = "AES/ECB/PKCS5Padding" ascii wide
        $s2 = "python -c 'import pty; pty.spawn" ascii wide
        $s3 = "status" ascii wide
        $s4 = "success" ascii wide
        $s5 = "sun.jnu.encoding" ascii wide
        $s6 = "java.util.Base64" ascii wide

    condition:
        all of ($fn*) or
        all of ($s*)
}
