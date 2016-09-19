---
layout: post
title: "Hunting For Vulnerabilities in Signal - Part 2"
date: 2016-09-19
categories: blog
---

We released information about two vulnerabilities that we discovered in
[Signal](https://whispersystems.org) in [part
1](http://pwnaccelerator.github.io/2016/signal-part1.html) of this blog
article series about what we found during an informal audit of the Signal source code.

# Impact of The MAC Bypass
As explained in the previous post, the bug we found allows you to append exactly 4GB of data to the original attachment. This modified attachment has now the size 4GB+X if the original encrypted file has the size X.

So what can you do with this? Many people would probably say "well not so much". This is not really correct, as we will show here. The crypto algorithm used here is AES in CBC mode. CBC stands for cipher block chaining. In simple terms, when decrypting a block, the previous block is also used in that operation via XOR.

This actually gives on control of part of the decrypted data. Technical details are given in the next section, but the implications are the following:

 - It is possible to append the encrypted file to itself.
 - It is possible to append part of the encrypted file to itself.
 - It is possible to take parts of the encrypted file, reorder them and append them to the original file.

Some parts of this file will be broken, but media codecs are usually robust. This is especially true for MP3 which we therefore used to create a little proof of concept.

The result of this can be seen in the following video:

{% include youtube.html video="brN6D9Fc4dc" %}

If an attacker knows the actual plain text (the data that our encrypted attachment is finally decrypted to), he might even do worse things such as controlling up to half of the decrypted data.

This attack is actually a known crypto attack which is what a knowledgeable commenter on Ars Technica also noted in [his post](https://arstechnica.com/security/2016/09/signal-fixes-bug-that-let-attackers-tamper-with-encrypted-messages/?comments=1&post=31900329) on the article about our initial publication.

The script used to attack the attachment server can be downloaded [here](https://github.com/pwnaccelerator/tools/tree/master/signal-proxy).

Following now in the following section is an exact description by @veorq about how to attack AES-CBC.

# Exploiting CBC Malleability

We've got a ciphertext `C = C[1] || C[2] || ... || C[n]` where
```
C[1] = E(K, IV ⊕ P[1])  
```
given the IV transmitted along with the ciphertext, and
```
C[i] = E(K, C[i–1] ⊕ P[i])  
```
for `i > 1`, where `P[i]`s are plaintext blocks and `E` is the
encryption function. Graphically, CBC looks like this:

<img src="cbc.png" width=600>

We want to extend `C` with additional ciphertext data. We don't know the
key `K` and we've got no encryption oracle therefore we can't forge a
whole new ciphertext for the plaintext of our choice. But we can do
something close to it.

The simplest we can do is append `C` to itself and build `C || C`. But
it won't exactly decrypt to `P || P`: when decrypting the second
occurence of `C[0]`, decryption will produce
```
D(K, C[0]) ⊕ C[n]
```
instead of `D(K, C[0]) ⊕ IV`. Since we can't modify the first `C` prefix
(whose MAC is verified), we can't modify `C[n]` so can't control the
plaintext block obtained. However, the second occurences of `C[2]`,
`C[3]`, ..., `C[n]` will be correctly decrypted to their original
plaintext blocks.

Likewise, if you create the ciphertext `C || C || ... || C`, consisting of the
original ciphertext repeated multiple times, then it will decrypt to `P
|| P' || P' || ... || P'`, where `P'` is the original plaintext but
with an incorrect first block.

But we can do better than this. We can add ciphertext material wherein
we totally control what half the blocks will decrypt to: create `C ||
C'`, where `C'[2] = C[2]', such that `C'[2]` will decrypt to:
``` 
P'[2] = D(K, C'[2])  ⊕ C'[1] = P[2] ⊕ C[1]  ⊕ C'[1] 
```
Here I just replaced `D(K, C'[2]) = D(K, C[2])` with `P[2] ⊕ C[1]`, as
per the CBC encryption of the original plaintext. Now note that we've
got to choose `C'[1]`, hence we can control the difference between the
original plaintext block `P[2]` and the block we want `C'[2]` to decrypt
to. That is, if we know the original plaintext or part of it (for
example, because we know its header), then we can choose what the new
ciphertext data will decrypt to.

Repeating the same trick for every two blocks, you can control one every
two blocks of the ciphertext data added, by exploiting degrees of
freedom in the preceding block.




