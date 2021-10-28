[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2020 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Licensing details for the app

### M2Crypto

This app uses the M2Crypto module, which is licensed under the MIT License (MIT), Copyright (c) Ng
Pheng Siong.

### typing

This app uses the typing module, which is licensed under the Python Software Foundation License
(PSF), Copyright (c) Guido van Rossum, Jukka Lehtosalo, Lukasz Langa, Ivan Levkivskyi.

## <span id="Requirements_2"></span> Requirements

Supported OS is CentOS 7+

Access your Phantom instance via Terminal and install following OS dependencies

            
            # Install library and its dependencies
            $~ sudo yum install python-devel openssl-devel gcc gcc-c++
            
          

## <span id="Keys_and_Certificates_3"></span> Keys and Certificates

To use this app you need to provide an RSA key pair (this consists of a public key and a private
key) and an X.509 certificate of said public key.

To generate a new RSA key pair, you could install and use OpenSSL on a CentOS 7 instance. Once
properly installed, execute the following commands to create key pairs and certificates.

            
            # Create a pair of keys
            $~ openssl req -newkey rsa:1024 -nodes -x509 -days 365 -out cert.pem

            # Rename the private key
            $~ mv privkey.pem key.pem
            
          

The generated keys and certificates will be used to configure a S/MIME Phantom asset.
