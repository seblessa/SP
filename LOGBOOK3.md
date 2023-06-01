
# Week #3 work log

## Identification

- The CVE-1999-2002 it's a critical vulnerability that gives root access to remote attackers, mostly in Linux systems.
- This vulnerability affected Linux systems from versions 2.0 to 5.1. 
- This vulnerability gave a potential attacker the ability to get root access which could led him to execute anything in the system or bypass any security measure implemented.


## Catalogation


- The vulnerability was reported in 1998-10-12.
- It was classified as a high risk and with a score of 10.0 in the CVSS system.

## Exploit

- The exploit of this vulnerability is connected to a region of memory used to temporarily store data while it is being moved from one place to another (buffer). 
- This problem also involves NFS wich is a Network File System that allows remote hosts to mount file systems over a network and interact with those file systems as though they are mounted locally. 
- When there is an overflow of the buffer in NFS mountd, remote attackes get root access. This happend primarly with linux systems.


## Ataques

- This type of attack was estimated to cost up to 25 000 $ on its release, and it had the potential to perform operations on a memory buffer, but it can read from or write to a memory location that is outside the intended boundary of the buffer. This has an impact on confidentiality, integrity, and availability.
- Successful attacks using this vulnerability were reported shortly after its discovery. 
- In conclusion attackers with malicious intent could use this vulnerability to disrupt critical services or cause financial damage.
