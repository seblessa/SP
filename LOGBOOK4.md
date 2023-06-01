# Week #4 work log

---

## Mandatory Tasks:


### Task 1: Manipulating Environment Variables

---

##### $ printev

Running `printenv` prints all the environment variables stored in the system.

```bash
$ printenv
```

<details><summary>$ output</summary>
<p>

```
SHELL=/bin/bash
SESSION_MANAGER=local/VM:@/tmp/.ICE-unix/2065,unix/VM:/tmp/.ICE-unix/2065
QT_ACCESSIBILITY=1
COLORTERM=truecolor
XDG_CONFIG_DIRS=/etc/xdg/xdg-ubuntu:/etc/xdg
XDG_MENU_PREFIX=gnome-
GNOME_DESKTOP_SESSION_ID=this-is-deprecated
GNOME_SHELL_SESSION_MODE=ubuntu
SSH_AUTH_SOCK=/run/user/1000/keyring/ssh
XMODIFIERS=@im=ibus
DESKTOP_SESSION=ubuntu
SSH_AGENT_PID=2029
GTK_MODULES=gail:atk-bridge
PWD=/home/seed
LOGNAME=seed
XDG_SESSION_DESKTOP=ubuntu
XDG_SESSION_TYPE=x11
GPG_AGENT_INFO=/run/user/1000/gnupg/S.gpg-agent:0:1
XAUTHORITY=/run/user/1000/gdm/Xauthority
GJS_DEBUG_TOPICS=JS ERROR;JS LOG
WINDOWPATH=2
HOME=/home/seed
USERNAME=seed
IM_CONFIG_PHASE=1
LANG=en_US.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
XDG_CURRENT_DESKTOP=ubuntu:GNOME
VTE_VERSION=6003
GNOME_TERMINAL_SCREEN=/org/gnome/Terminal/screen/0ed6cd2f_f48f_47ad_8bcf_6007c1df880c
INVOCATION_ID=f4e2e0e67ffc40069a051f260ed1b9d2
MANAGERPID=1815
GJS_DEBUG_OUTPUT=stderr
LESSCLOSE=/usr/bin/lesspipe %s %s
XDG_SESSION_CLASS=user
TERM=xterm-256color
LESSOPEN=| /usr/bin/lesspipe %s
USER=seed
GNOME_TERMINAL_SERVICE=:1.97
DISPLAY=:0
SHLVL=1
QT_IM_MODULE=ibus
XDG_RUNTIME_DIR=/run/user/1000
JOURNAL_STREAM=9:35550
XDG_DATA_DIRS=/usr/share/ubuntu:/usr/local/share/:/usr/share/:/var/lib/snapd/desktop
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:.
GDMSESSION=ubuntu
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
_=/usr/bin/printenv
```

</p>
</details>
<br />


![image]()



##### $ export | $ unset
The command `export` can be used like this:

```bash
$ export x=5
```
Then `x` is saved as an environment variable with the value of *5*.

We can use the command `echo` to print out the value of the stored environment variable referred int the command arguments:

```bash
$ echo $x
```

If we want to remove the value of *x* we can use the command `unset`:

```bash
$ unset x
```

Now if we used `echo` the same as before the output becomes null as it was before we used the command `export` for the first time.


<br />

### Task 2: Passing Environment Variables from Parent Process to Child Process

---

#### Step 1:
In this step we created a file called myprintenv.c in the virtual machine where we wrote code. 
Then, we compiled the c code, creating a file a.out with the compiled code. 
The next step was to the content of a.out to a new file, so we did the following command: a.out > file. 
We did not have "file" but with this command it is automatically created with the content of a.out. 

#### Step 2 and 3:
In this step we changed the code by commenting the statement in the child process case and uncommenting the statement 
in the parent process case. Then we created a file called "step2" and compared it with the output of the first file.
After using command diff with both files we can conclude that they are equal. We can conclude that there is inheriting variables between
parent and child processes.

<br />


### Task 3: Environment Variables and `execve()`

---

#### Step 1:
We compiled and ran the program successfully and no output was given by the program. 

#### Step 2:
After the suggested modification, the program gave the same output as task 1 output using printenv.


#### Step 3:

As there are no restrictions, the program is capable to return the environmental variables.
<br />


### Task 4: Environment Variables and `system()`

---
After compiling and running the program, we verified that the program returned the environment variables equally to the previous points.


<br />


### Task 5: Environment Variable and `Set-UID` Programs

---

After setting environment variables using the "export" command and running a program, it can be observed that not all variables from the parent process are passed to the child process. Usually, the child process receives a copy of the parent process environment, but some important environment variables, such as "ld_library_path", may not be passed to the child process. In this specific case, only the "path" and "var" variables were inherited by the child process.

<br />


### Task 6: The PATH Environment Variable and `Set-UID` Programs

---
After disabling the attack prevention measures, we were able to run our own program instead of /bin/ls. By changing the value of the "path" variable and running the program again, we were able to run it with root privileges.

<br />
