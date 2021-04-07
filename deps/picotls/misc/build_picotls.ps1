# Match expectations of picotlsvs project.
mkdir $dir\include\
foreach ($dir in "$Env:OPENSSLDIR","$Env:OPENSSL64DIR") {
    if ($dir) {
        cp "$dir\lib\libcrypto.lib" "$dir"
        cp C:\OpenSSL-Win32\include\openssl\applink.c "$dir\include\openssl"
        echo "Copied applink.c to $dir\include\openssl"
    }
}

# msbuild "/p:Configuration=$Env:Configuration" "/p:Platform=$Env:Platform" /m picotlsvs\picotlsvs.sln
