This is a tool for playing with Linux 5.12's new Landlock feature.

Landlock lets processes lock themselves into a subset of their file
access permissions.

It's a fork of the `samples/landlock/sandboxer.c` tool by Mickaël
Salaün, which ships with the kernel source, changing environment
variable parsing to flag parsing, and making it easier to compile
standalone and play with the feature. It's not meant as a serious
sandboxing tool.

Example:
```
root(302)@virtual:~# ./lljail -r /usr -r /bin -rw /tmp -r /etc -r /root -- /bin/bash
root(681)@virtual:~# echo lol > cat  # fails (read-only directory)
bash: cat: Permission denied
root(681)@virtual:~# cd /tmp
root(681)@virtual:/tmp# echo lol > cat  # succeeds (read-write directory)
root(681)@virtual:/tmp#
```

Remark: Landlock's support will keep the proces from opening files for
reading and writing, but some syscalls can currently not be restricted
yet, such as `stat()`.

You can see this for example when using the `file` utility: It will
still detect that the file is there, using `stat()`, but it only
recognizes its content once it has the read permissions.

```
root(207)@virtual:~# ./lljail -r /usr -r file /etc/magic -- /bin/file text.txt
text.txt: writable, regular file, no read permission
root(207)@virtual:~# ./lljail -r /usr -r file /etc/magic -r file text.txt -- /bin/file text.txt
text.txt: ASCII text
```
