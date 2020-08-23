## 1m-block
* The modified version of [netfilter](https://github.com/bob-9th/netfilter)
### Requirement
#### Ubuntu
```
sudo apt install libpcap-dev libnetfilter-queue-dev
```
### Usage
```
cmake .
make
./1m-block <host.txt>
```
* <b>You must run as root.</b>
* The program was tested on 5.4.0-42-generic #46-Ubuntu.

### host.txt
* URL to forbid accessing. (only apply to http packet)