# Mockingjay_POC

**Preface: I'm learning ok?**

Very **rough and incomplete** draft [I wrote a while back](https://www.linkedin.com/posts/codyread13_cybersecurity-redteam-malware-activity-7081354214920114177-UsQX?utm_source=share&utm_medium=member_desktop) of the "Mockingjay" technique based on Namazso's original discovery on the [Unknown Cheats](https://www.unknowncheats.me/forum/anti-cheat-bypass/286274-internal-detection-vectors-bypass.html) forum and the recent [Security Joes](https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution) article.

The idea is to have your malware exist in a **naturally RWX allocated memory region** located in a trusted module and process of which the module is loaded, leaving out the need for common process injection WIN/NT API calls. The technique is supposed to be threadless, but I was unable to replicate without creating a thread which is a major IOC on it's own, especially when facing ETW powered EDR products.

With that being said, **I plan to continue development of this POC once other Red Team projects complete and this specific Purple Team project resumes.** For now it can exist here for my own use and be used as inspiration for other POCs.

## TO-DO
* Make the POC threadless inject as mentioned in the above article
* Convert self_inject from memcpy to NtWriteVirtualMemory
* Implement various evasion techniques for Purple Team testing
	* Most likely will be sub-POCs. NTAPI, Direct Syscall, Indirect Syscall, etc.
* Can it be BOF'd?