---
title: "Fuzzing FreeImage to uncover vulnerabilities"
description: Fuzzing freeimage
summary: Fuzzing FreeImage with American Fuzzy Lop in the hope to uncover vulnerabilities.
draft: false
tags: ["cyber security", "fuzzing"]
---

Fuzzing FreeImage with American Fuzzy Lop in the hope to uncover vulnerabilities.

## Introduction

Without a doubt, one of the better software application security testing techniques for the last decades has been [fuzzing](https://en.wikipedia.org/wiki/Fuzzing) or fuzz testing. While security testing requires a test suite and test oracle, fuzzing automatically generates test cases and uses a simple oracle to determine whether the fuzz test succeeded, i.e. the software under test crashes. 

## American Fuzzy Lop
Whereas older fuzzers needed a lot of manual effort to setup and configure, evolutionary coverage-guided fuzzers such as [AFL](https://lcamtuf.coredump.cx/afl/) (yes, named after the actual cute breed of rabbits) have greatly increased ease of use. There is no more reason *not* to incorporate fuzzing in a secure development lifecycle. 

AFL wraps around C and C++ compilers and instruments a binary during compilation. At runtime, the program uses this instrumentation to build a coverage graph to determine what parts of a program have been visited during fuzz testing. We do not only want to fuzz the happy path of software, on the contrary, the less tested / underdeveloped paths are were most bugs reside. 

## Test cases

By mutating an initial set of test cases, AFL can test software with increasing coverage without any knowledge of the structure of the input data. However, the initial set of test cases is an important consideration, because the quality of the fuzz test depends on it. Ideally, for software that consumes multiple different input formats, one wants multiple intial test cases to cover these different file formats.

To this end, [Radamsa](https://gitlab.com/akihe/radamsa) has been used to mutate an initial set of file formats to be used with AFL. Further, [AFL-cmin](https://afl-1.readthedocs.io/en/latest/tips.html) has been used to prune redundant cases or cases that lead essentially test the same code paths. 

## Target

Software that is most easy to fuzz with AFL are those that support command line input, accept a wide range of input formats and has few vulnerabilities. Having few vulnerabilities is either a sign of high quality development standards, or the absence of extensive testing and scrutiny. One project that fits these criteria (except direct for command line input, more on that later) is the [FreeImage](https://freeimage.sourceforge.io/) project, which is a: 

>FreeImage is an Open Source library project for developers who would like to support popular graphics image formats like PNG, BMP, JPEG, TIFF and others as needed by today's multimedia applications. FreeImage is easy to use, fast, multithreading safe, compatible with all 32-bit or 64-bit versions of Windows, and cross-platform (works both with Linux and Mac OS X).

At the moment of writing, fewer than ten vulnerabilities had been reported. Version 3.18.0 has been chosen as the version to perform fuzz testing on. 

FreeImage supports 33 image file formats. Generating test cases for every file format would be extremely time-consuming, so the list of formats to test against has been reduced to the following five common formats: JPEG/JPG, GIF, WEBP, IFF/LBM and TGA.

## Test suite
The generous developers of FreeImage actually provide a test set of images of [various formats](https://sourceforge.net/projects/freeimage/files/Test%20Suite%20%28graphics%29/2.5.0/) to test against, scraped from Google Images and public Github repositories. From this suite, 270 images have been chosen, of which 107 JPEG, 46 GIF, 40 WEBP, 43 IFF, and 34 TGA images. 

Radamsa was applied to this set of images, which produced 10000 mutations:

```
radamsa -o All/fuzz-%n.%s -n 10000 All/*
```

The total set of mutations has been pruned with AFL-cmin to find the smallest subset of imagse that result in the same execution flow:

```
sudo ./afl-cmin -i All/ -o All-minimized/ -m 8000 -t 2000 ~/fuzzing_assignment/a.out @@
```

The final set for testing consists of 992 images with a roughly equal distribution of file formats as previously described. 

## Test and Results

Since FreeImage is a library, it does not support direct command line input, as it is meant to be used and linked when developing software. A small wrapper has been written to load FreeImage and pass command line input to the library:

```c
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>

#include "FreeImage.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FIMEMORY *mem;
    FIBITMAP *dib;
    FREE_IMAGE_FORMAT fif = FIF_UNKNOWN;
    BOOL bSuccess = FALSE;

    FreeImage_Initialise(true);

    mem = FreeImage_OpenMemory(const_cast<uint8_t *>(data), size);
    if (!mem)
        return 0;

    dib = FreeImage_LoadFromMemory(FIF_TIFF, mem, TIFF_DEFAULT);

  	if(dib) {
  		// try to guess the file format from the file extension
  		fif = FreeImage_GetFileTypeFromMemory(mem);
  		if(fif != FIF_UNKNOWN ) {
  			// check that the plugin has sufficient writing and export capabilities ...
  			WORD bpp = FreeImage_GetBPP(dib);
  			if(FreeImage_FIFSupportsWriting(fif) && FreeImage_FIFSupportsExportBPP(fif, bpp)) {
  				// ok, we can save the file
  				bSuccess = FreeImage_Save(fif, dib, "testfile", 0);
  				// unless an abnormal bug, we are done !
  			}
  		}
  	}

    FreeImage_Unload(dib);
    FreeImage_CloseMemory(mem);
    FreeImage_DeInitialise();

    return 0;
}
```

AFL was run against this wrapper on an Azure virtual machine in the cloud for a little bit over a week (7+ days) with the following command:

```
afl-fuzz -t 2000+ -i test-suite/All/ -o ~/fuzzing_assignment/out-dir-afl-only/
~/fuzzing_assignment/a.out @@

```

| | AFL |
|-|-|
No. intial files | 270 |
No. mutations    | 7.46 million|
Time             | 7 days, 22 hrs |
No. unique crashes | 26 | 
No. unique hangs | 66 |


This run led to the following potential crashes:

| Tool | #  | Input file | Bug                   | Location                  |
|------|----|------------|-----------------------|---------------------------|
| AFL  | 1  | src:000056 | heap-buffer-overflow  | FreeImage\_LoadFromHandle |
| AFL  | 2  | src:000056 | heap-buffer-overflow  | FreeImage\_LoadFromHandle |
| AFL  | 3  | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 4  | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 5  | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 6  | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 7  | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 8  | src:000056 | heap-buffer-overflow  | FreeImage\_SaveToHandle   |
| AFL  | 9  | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 10 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 11 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 12 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 13 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 14 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 15 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 16 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 17 | src:000056 | heap-buffer-overflow  | FreeImage\_SaveToHandle   |
| AFL  | 18 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 19 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 20 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 21 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 22 | src:000056 | error handling        | LibJXR Aborted            |
| AFL  | 23 | src:000056 | stack-buffer-overflow | FreeImage\_WriteMemory    |
| AFL  | 24 | src:000056 | heap-buffer-overflow  | FreeImage\_SaveToHandle   |
| AFL  | 25 | src:000056 | heap-buffer-overflow  | FreeImage\_SaveToHandle   |
| AFL  | 26 | src:000056 | heap-buffer-overflow  | FreeImage\_SaveToHandle   |
| AFL  | 1 | 1.webp | stack-overflow | \_IO\_sgetn in fread in ReadProc in LibRaw:get4  | 


Most crashes were found from a single JPEG file (src:000056.jpg), however one crash stood out that resulted from a malformed WEBP file. Looking through the previously reported [CVE's](https://www.cvedetails.com/product/32505/Freeimage-Project-Freeimage.html?vendor_id=15676) for FreeImage shows that most of the JPEG related crashes have been found already. The WEBP crash however seems to be unique. After running AFL again with address sanitization again, we get more insight into the stack overflow:

> AddressSanitizer: stack-overflow on address 0xff194efc  
>    #0 0xf79d933f  (/lib32/libasan.so.5+0x6a33f)  
>    #1 0xf5c21e07  (/lib/libfreeimage.so.3+0x1a6e07)  
>    #2 0xf6dd10ac  (/lib/libfreeimage.so.3+0x13560ac)  
>    #3 0xf6dd174c  (/lib/libfreeimage.so.3+0x135674c)  
>    #4 0xf6dd174c  (/lib/libfreeimage.so.3+0x135674c)  
>    ...  
>    #246 0xf6dd174c  (/lib/libfreeimage.so.3+0x135674c)

Looking deeper into the issue, we see that this test case causes FreeImage to enter a recursive function and never reach a base case. After too many recursive calls, the program crashes due to a stack overflow. The test case that causes the crash looks like this:

> 000  52 49 46 46 30 30 30 30  30 30 30 30 30 30 30 30     |RIFF000000000000|  
> 010  ec ff ff ff 30 30 30 30  30 30 30 30 30 30 30 30     |....000000000000|  
> 020  30 30 30 30 30 30 30 30  30 30 30 30 30 30 30 30     |0000000000000000|

The first four bytes spell out RIFF, which stands for Resource Interchange File Format, of which WEBP is an example. Changing the extension of the test case results in the same stack overflow. It seems that FreeImage chooses to ignore the file extension and tries to identify the file format by the contents of the file. This bug cannot be attributed to previous CVE's and warrants a new bug report!

## Related software

FreeImage lists a number of [software tools](https://freeimage.sourceforge.io/users.html) that makes use of the FreeImage library. Although the software does not list the specific version of FreeImage, it is interesting to try to reproduce this crash with these other software tools as the mere use of FreeImage as a library makes this software also vulnerable.

Testing a random sample of related software, namely BR's PhotoArchiver, Kujawiak Viewer, Photo Browser and Image Walker each crash when providing the mutated WEBP file. The software PixFiler and SmartImageDenoiser handle the crash more gracefully by outputting a warning message. This goes to show that extra sanitization checks on the libraries that you use may go a long way in preventing your software from crashing. Unfortunately, none of the software crashes led to exploitable vulnerabilities :disappointed:.

## Conclusion

Getting acquainted with AFL and fuzzing techniques has been a very interesting exercise. A unique crash was found that warrants a report to the developers. the excitement of seeing the potential crashes and hangs in AFL go up is almost addictive. I was a bit disappointed that I was unable to find any exploitable vulnerabilities but I learned a lot!