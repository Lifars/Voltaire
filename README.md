# Voltaire
Voltaire is a memory image scanning and analysis tool. It is based on Volatility framework to scan the memory image and store the results in database as well as in file. With the principal of Find Evil - Know Normal, it detects potential malware processes.

Supports investigations of the following memory images:
- VistaSP0x64
- VistaSP0x86
- VistaSP1x64
- VistaSP1x86
- VistaSP2x64
- VistaSP2x86
- Win10x64
- Win10x64_10586
- Win10x64_14393
- Win10x86
- Win10x86_10586
- Win10x86_14393
- Win2003SP0x86
- Win2003SP1x64
- Win2003SP1x86
- Win2003SP2x64
- Win2003SP2x86
- Win2008R2SP0x64
- Win2008R2SP1x64
- Win2008R2SP1x64_23418
- Win2008SP1x64
- Win2008SP1x86
- Win2008SP2x64
- Win2008SP2x86
- Win2012R2x64
- Win2012R2x64_18340
- Win2012x64
- Win2016x64_14393
- Win7SP0x64
- Win7SP0x86
- Win7SP1x64
- Win7SP1x64_23418
- Win7SP1x86
- Win7SP1x86_23418
- Win81U1x64
- Win81U1x86
- Win8SP0x64
- Win8SP0x86
- Win8SP1x64
- Win8SP1x64_18340
- Win8SP1x86
- WinXPSP1x64
- WinXPSP2x64
- WinXPSP2x86
- WinXPSP3x86

## Requirement

- Python 2.6 or later, but not 3.0. http://www.python.org
- Volatility, but not Volatility 3. https://github.com/volatilityfoundation/volatility#start-of-content

## Downloading Voltaire

The latest stable version of Voltaire will always be the master branch of the GitHub repository. You can get the latest version of the code using the following command:
```shell
git clone https://github.com/Lifars/Voltaire.git
```

## Quick Start

1. Clone the latest version of Voltaire from GitHub:

    ```shell
    git clone https://github.com/Lifars/Voltaire.git
    ```

2. See available options:

    ```shell
    bash ./voila.sh -h
    ```

3. To scan and analyze the memory image and to make sure Voltaire supports that image type, run
    `bash ./voila.sh <imagefile> `

   Example:

    ```shell
    bash ./voila.sh  ~/Downloads/xp-laptop-2005-07-04-1430.img
    ```
    
## Licensing and Copyright
Copyright (C) 2020 LIFARS LLC

All Rights Reserved

https://github.com/Lifars/Voltaire/blob/master/LICENSE
    
    
## Support

This is provided "as is". No specific support will be provided. We will try to answer questions.

## Contact

For information or requests, visit our website https://lifars.com/
