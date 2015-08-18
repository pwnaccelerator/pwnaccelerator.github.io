---
layout: post
title: "Self Defense - Patching the Stagefright Patch"
date: 2015-08-17
categories: blog
---

**DISCLAIMER: The things I describe below and fiddiling with executeable bits in general are only intended for people knowing what they are doing. It might introduce new bugs, prevent you from future updates, brick your phone and probably give your dog diarrhea while he is home alone.**

So as you might have already learned Google messed up their patching leaving
your Android device still vulnerable to nasty integer overflow vulnerabilities.
Several blogposts already discussed this such as the ones from [Exodus][exodus-sf],
[Fortigate][fortigate-sf] and there is a new CVE identifier CVE-2015-3864 adressing
this.

Despite being fixed in the AOSP repositories until today I did not see any OTA patch
that fixes CVE-2015-3864. Actually the majority of users is totally left alone by vendors that got money from them. I guess
this says much about the importance of security for Android vendors including Google. Google even claims the bad patch
is not so bad because you have ASLR. Following that logic they did not need to issue any patch at all...

This is really annoying me, especially since I got a few test devices here that I rely on, and which are still vulnerable. So I took some break and tried to fix at least some of the overflows.

If you want to fix stagefright yourself you basically have three options:

 * Mititgation (some [good advice][zimperium-sf-tips] from Zimperium)
 * Compiling libstagefright from the AOSP sources
 * Patching the libstagefright.so binary

The first two options were not good enough for me as most of the mitigations are incomplete and I don't want to set up a full Android build environment (actually I can't at all since for my device since it's some custom Android build for which I don't have the source).

So I went with option 3 and fired up my favorite patching tool [Hopper][hopper-app].

As I would like to create the stagefright patch in my lunch break
this means I don't want to do too much magic on the binary. So the actually
I want to avoid adding new code segments, hook any functions, instrument, etc.
So let's focus on modifications that we could do using a hex editor.

If you look at the original unpatched source code in *media/libstagefright/MPEG4Extractor.cpp*
you will see that after creating the uint8_t buffer object, memcpy is guarded by "if (size > 0)".

{% highlight c++ %}
	case FOURCC('t', 'x', '3', 'g'):
	{
	    uint32_t type;
	    const void *data;
	    size_t size = 0;
	    if (!mLastTrack->meta->findData(
		    kKeyTextFormatData, &type, &data, &size)) {
		size = 0;
	    }
	    uint8_t *buffer = new (std::nothrow) uint8_t[size + chunk_size]; // INT OVERFLOW HERE
	    if (buffer == NULL) {
		return ERROR_MALFORMED;
	    }
	    if (size > 0) {
		memcpy(buffer, data, size);
	    }
{% endhighlight %}


The check was probably inserted to speed up things (saving a function call) or
(unlikely) because a call to memcpy with zero size and uninitialized pointers counts as
undefined behaviour.
Actually here the only possible uninitialized pointer argument could be "const void *data;"
which should come from "mLastTrack->meta->findData(kKeyTextFormatData, &type, &data, &size)".
In practice however the Android (and GNU) implementation of memcpy will treat calls
to memcpy with a size of zero and an uninitialized src-argument as a no-op.

So why not trade the "unnecessary" (please feel free to prove me wrong) check for one
that will catch the overflow.

We disassemble the original "libstagefright.so" from a Lenovo device running
Android 5 and look for the assembly resulting from the code above:

{% highlight text %}
000b3618         blx        _ZNK7android8MetaData8findDataEjPjPPKvS1_@PLT	; android::MetaData::findData(unsigned int, unsigned int*, void const**, unsigned int*) const
000b361c         cbnz       r0, 0xb3620

000b361e         str        r0, [sp, size]

000b3620         ldr        r1, = 0xfffff770                                    ; 0xb36f0, XREF=_ZN7android14MPEG4Extractor10parseChunkEPxi+10724
000b3622         ldr        r0, [sp, chunk_size]
000b3624         ldr        r1, [r5, r1]
000b3626         ldr        r5, [sp, size]
000b3628         add        r0, r5
000b362a         blx        _ZnajRKSt9nothrow_t@PLT_512268
000b362e         mov        sl, r0
000b3630         cmp        r0, #0x0
000b3632         beq        error_malformed

000b3634         ldr        r2, [sp, size]
000b3636         cbz        r2, skip_memcpy ; if (size > 0)

000b3638         ldr        r1, [sp, var_D0]
000b363a         blx        memcpy@PLT

	     skip_memcpy:
000b363e         ldr        r0, [r6, #0x78] 
{% endhighlight %}

Okay great, at 0xb3634 "size" is loaded from the stack and put into r2 (third argument
by calling convention used on Android-ARM). Next if r2 is zero the call to memcpy is skipped.

So if we don't check "size > 0" we get one instruction for us to catch the overflow. But
how to catch a numeric overflow in one instruction?

CPU flags and conditional branching to the rescue!

Using Hopper we change the assembly a bit:

{% highlight text %}
000b3618         blx        _ZNK7android8MetaData8findDataEjPjPPKvS1_@PLT	; android::MetaData::findData(unsigned int, unsigned int*, void const**, unsigned int*) const
000b361c         cbnz       r0, 0xb3620

000b361e         str        r0, [sp, size]

000b3620         ldr        r1, = 0xfffff770                                    ; 0xb36f0, XREF=_ZN7android14MPEG4Extractor10parseChunkEPxi+10724
000b3622         ldr        r0, [sp, chunk_size]
000b3624         ldr        r1, [r5, r1]
000b3626         ldr        r5, [sp, size]
000b3628         adds       r0, r0, r5
	                               ; bail out on overflow:
000b362a         bhs        error_malformed

000b362c         blx        _ZnajRKSt9nothrow_t@PLT                             ; operator new[](unsigned int, std::nothrow_t const&)
000b3630         mov        sl, r0
000b3632         cmp        r0, #0x0
000b3634         beq        error_malformed

000b3636         ldr        r2, [sp, size]
000b3638         ldr        r1, [sp, var_D0]
000b363a         blx        memcpy@PLT
000b363e         ldr        r0, [r6, #0x78]
{% endhighlight %}

By changing the *add* instruction at address 0xb3628 to *adds* (add with flags),
the carry flag is set when the target register can not hold the result. We use
a conditional branch instruction *bhs* (*bcs*) to bail out if that is the case.

Checking for arithmetic overflows in asm is pretty elegant right? Not the minefield that C/C++ represents in that in this regard.

So now we have before:


![Vulnerable to CVE-2015-3864](/images/posts/2015-08-17/screenshot-vuln.jpg)


And afterwards CVE-2015-3864 is fixed:


![NOT Vulnerable to CVE-2015-3864](/images/posts/2015-08-17/screenshot-fix.jpg)


Of course we are still vulnerable to the various other bugs with CVE's that were detected besides this one integer overflow..still one bug less, and a good excercise!

Handling of this vulnerability shows that vendors don't care about your security, so we need to take action!

If you are interested here is a version of libstagefright for the Lenovo Vibe X2 that has the patch:

 * [Lenovo X2 Android 5.0, X2-AP_S224_150709 (tested and works)][x2-patchedlib]

If you create patches on your own for other devices, feel free to contact me.

[fortigate-sf]:	https://blog.fortinet.com/post/stagefright-telegram-stage-left-whatsapp-stage-right
[exodus-sf]:	http://blog.exodusintel.com/2015/08/13/stagefright-mission-accomplished/
[zimperium-sf-tips]:	https://blog.zimperium.com/how-to-protect-from-stagefright-vulnerability/
[hopper-app]:	http://www.hopperapp.com
[x2-patchedlib]:	https://github.com/pwnaccelerator/stagefright-cve-2015-3864/tree/master/lenovo-vibe-x2/android5.0-x2-ap_s224-150709

