---
layout: post
title: "Vendors, Disclosure, and a bit of WebUSB Madness"
date: 2018-06-16
categories: blog
author: Markus Vervier
---

In the light of recent events here are my (Markus Vervier) personal and final thoughts on what happened with YubiCo and our WebUSB research.
If you want to skip the background and read about the recent events just scroll down to "The Big Surprise".

# The Background - WebUSB vs. U2F

In mid 2017 we started to research a bit into WebUSB. Similar to nearly every other security expert in the field
we thought it is a dangerous idea. We soon came up with the idea to circumvent U2F using WebUSB.

**Was there any specific bug to report before we gave the talk? No, because it was widely discussed in the security scene that WebUSB is a bad idea. We
believe we have demonstrated that by showing how it breaks U2F. There was no single issue to report to Google or Yubico,
but a public discussion to trigger so WebUSB is fixed.**

As you might know
U2F was regarded as "unphishable"[^1] because authentication is bound to an origin.

This means even if you trick a user into entering his facebook.com credentials on "https://fakebook.com", U2F still
prevents bad things happening because there is no authentication key registered for "fakebook.com" that works on "facebook.com". The browser ensures that the origin is respected and only passes authentication requests for the current origin to the U2F authentication
token. A simplified flow looks like this:

![](/images/posts/2018-06-15/u2f-flow-simplified.png){:width="100%"}

So far so good. Introducing WebUSB, a website can now directly talk to a USB device. We quickly came up with the idea
to use this to sort of "emulate" the browser. Being able to talk to the U2F device directly, authentication requests for any origins
can be processed on any web site regardless the origin.

We realized this is not limited to U2F / FIDO and developed a generic proxy that allows to **forward
any USB device exposed to WebUSB to a remote system**. This includes SmartCard readers, GPG keys, WebCams, Keyboards, and much more.
If you are interested in more details, you should watch our talk recorded at Offensive Con in Berlin on 2018-02-16:

<iframe width="560" height="315" src="https://www.youtube.com/embed/pUa6nWWTO4o" frameborder="0" allowfullscreen></iframe>

As a response to this, an article[^2] on wired.com was written by Andy Greenberg and ultimately Google decided to
activate[^3] a kill switch to disable WebUSB remotely.


# WebUSB Part II, HID Access and Further Research

Already before Offensive Con we discovered that HID access seemed to be possible under Windows. We did not show this
because we also discovered other bugs regarding HID (memory corruptions) in Chrome that we did not have time to
investigate and therefore did not report yet. Talking about this on a public conference would not have been ethical.

# WebUSB Part III, Contacted by Yubico

After the wired.com article was released, attention to our talk increased a lot. While we got much personal response from
attendees of Offensive Con and other people, now we were contacted[^4] by Yubico:

![](/images/posts/2018-06-15/jesper-contact.png)

On March 2nd we did a call with Jesper where he was asking us to explain the issue because they wanted to "understand what's going on".
We did not contact YubiCo before because we did not believe the possible attacks were a flaw of YubiCo products
and also made sure to stress this in our talk. The issue was a design problem and inherent issue of WebUSB and U2F
conflicting in terms of security.

We showed Jesper our unreleased slides, PoCs, videos. We discussed the impact. We also told him we are still researching WebUSB
and apparently WebUSB access to HID class devices seems to be possible. He thanked us and promised to send us some YubiKeys as a
"thank you".

On 2018-03-03 we submitted the HID issue and a memory corruption issue to the Chromium bug tracker as issue #818472[^5].

# The Big Surprise

Time went on, we submitted a follow up talk to Blackhat and Defcon, neither of them accepted it. Personally
that has been disappointing, but nobody is entitled to have a slot at these conferences and it is their decision.

Then on 2018-06-13 we got word from Francisco Alonso (@revskills) who mentioned a Twitter post by Yubico claiming
to have found and fixed a serious issue with WebUSB and getting a 5.000 USD bounty from Google for that. It was exactly our research and their "contribution" was that they apparently verified that HID access was possible
under Windows and OS X.

The credit given was "The researchers claimed", no link, no names, nothing detailed mentioned. Instead the text was very keen
on pointing out that our research was mistaken and Yubico got it right:

![](/images/posts/2018-06-15/yubico-incorrect.png){:width="100%"}

Of course this outraged me a lot and I made it clear on Twitter[^6] that this is unacceptable! Especially since I remembered
what we had discussed with Yubico and what we had submitted to Chromium and Google. Next morning
my co-presenter got word of it too and made a clear statement[^7]. Yubico contacted me in the night (SVP Development)
promising to get it right. I do not want to quote the private conversation that followed but
basically Yubico claims parallel research, and that when we had the call they already had a PoC and just wanted to confirm
what we had. Also that they were working with Google without telling us.

So to get this clear: Yubico had internally replicated our work, contacted us to gather information about
what we have not released so far, asked us for help to create a PoC, BUT DID NOT TELL US ANYTHING ABOUT THEIR INTENTIONS?!
Then went to Google, two days later submitting a comprehensive analysis of the research, claiming
to have new original content and gaining a 5.000 USD bounty for this (which they donated to charity, maybe
because it did not really feel right?)!

As for our bug submitted two days before we were declined a bounty and someone commented that "HID access is already known".
As of today the issue is still restricted and I will not post the full information therefore. But I can
post what we submitted in the first place showing we submitted a PoC and two issues, a memory corruption
and the HID access also submitted by Yubico:

![](/images/posts/2018-06-15/chromium-bug-818472.png){:width="100%"}

**Why did Google VRP award the bounty to them? Unknown.**

**Did anyone from Google VRP contact us about this? Nope.**

Following the shitstorm and conversations they added credit to their advisory (without marking
their changes)

Remarkably they also edited their timeline.

The original timeline was:

![](/images/posts/2018-06-15/yubico-timeline-orig.png){:width="100%"}

Their updated timeline looks like this:

![](/images/posts/2018-06-15/yubico-timeline-new.png){:width="100%"}

I do not know what "private outreach" means and why Yubico lied about being unable to replicate
our findings in a call on March 2nd, even though they had it apparently working internally.

Also I never heard anything from Google VRP even though I reached out. I would love to hear what
the reason is to give a bounty to Yubico while declining it to us, even though we reported it first
and also another issue (memory safety violation). Also there seems to be a kind of relationship
between Google and Yubico that I would love to know more about.

**By all means let the girls who code keep
their donation, but honestly I do not know why I should ever take on the hassle to report anything in Chromium again.**

On top of this there are apparent press releases[^8] going on by Yubico, trying to exploit this
issue marketing wise:

![](/images/posts/2018-06-15/mobileidworld.png){:width="100%"}

On top of everything this is just pure irony.

# Final Words

To make it clear: I'm not after fame, credits, or want to take some bounty away from @girlswhocode!
Things like these are just disappointing and I refuse to let a vendor get away with such behavior.
So what are my takeaways from this for free-time pro bono research adventure? (Being contracted for work
is an entirely different game.)

I always believed in working with vendors to get issues fixed,
but things like this makes you wonder why people hoarding exploits, doing full disclosure, or selling them have an
apparently easy and prosper life.

On a professional level I never had any problems with work and research when being contracted to do security audits,
expectations and resonsibilities are clear.
But as a private researcher it seems like being nice just means trouble.

# References

[^1]: https://www.yubico.com/2017/10/creating-unphishable-security-key/
[^2]: https://www.wired.com/story/chrome-yubikey-phishing-webusb/
[^3]: https://bugs.chromium.org/p/chromium/issues/detail?id=819197#c11
[^4]: https://twitter.com/jjdives/status/969282300960636928
[^5]: https://bugs.chromium.org/p/chromium/issues/detail?id=818472
[^6]: https://twitter.com/marver/status/1007036989764403200
[^7]: https://twitter.com/antisnatchor/status/1007150498510753792
[^8]: https://8.com/yubico-strong-example-906133/
