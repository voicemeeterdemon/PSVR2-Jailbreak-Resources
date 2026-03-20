# PSVR2 Jailbreaking
I want to start this by saying I am no expert in low level things like this, I was learning a lot of it while doing this.

# Vulns
There are 3 things I found.

## OOB Heap Leak & Arb Read
(sieusb/authentication.c)<br />
Leads into a arb read and KASLR bypass. Heres a leak of what Kaitlyn said<br />
![meow](arbread.png)

## Stack overflows
(sieusb/authentication.c line 466) & (sieusb/authentication.c line 530)<br />
the second stack overflow POC isn't included here because its pretty much the same as the first one.

# What I hope to achieve
The whole Bnuuy Solutions staff are gatekeeping so they can release everything and get all of the clout, by releasing my findings I hope someone else can root it and take the clout from them lol<br />

# backup
This repo might get taken down to do posting the firmware, heres a backup incase that happens. https://gofile.io/d/9YPKqS
