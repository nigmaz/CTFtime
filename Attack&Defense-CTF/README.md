# Attack & Defense CTF

> https://github.com/HITB-CyberWeek/ctf-training-session-2021/tree/main/services/nasarasa

## [1]. Cung cấp proxy của máy chủ service:

> Máy tính cá nhân -> Proxy -> Máy chủ chứa service (Bài thi).

- Proxy và cách cấu hình, các tính năng proxy.
- Quản trị máy chủ, mô hình mạng
- Học ssh: cài máy ảo linux, học các lệnh cơ bản, cài đặt gói, chạy ứng dụng,... bằng command line
- Học filesystem, phân quyền trên linux
- Dựng một trang web lên máy chủ linux, có database
- Chạy một bài pwn lên server, dùng netcat để listen port
- Cài đặt một http proxy lên server. Proxy listen port 80 rồi forward sang web/pwn port 8080, sau đó print data gửi qua proxy, code hoặc viết rule chặn lọc, sửa data gửi qua lại.
- Rule

  - Chặn payload có chứa 1 string nào đó
  - Sửa 1 string trong payload thành string khác
  - Chặn response có string nào đó
  - Sửa string trong response thành string khác

- Học firewall
  - Cấu hình iptables để:
    - Chặn IP truy cập đến 1 port
    - Chặn gói tin có chứa 1 string nào đó
    - Forward toàn bộ gói tin đến 1 port sang 1 server khác
- Học tcpdump:
  - Dump traffic từ 1 port, 1 card mạng => Xem trực tiếp hoặc mở bằng wireshark
- Học netcat để:
  - listenport, chạy bài pwn hoặc crypto
- Học các ngôn ngữ web cơ bản: lập trình, cài lib, import lib, build, deploy

## [2]. Cung cấp máy chủ service:

- Có thể tác động thẳng vào dịch vụ ví dụ như code vá lỗ hổng để phòng thủ khi được cung cấp cả hạ tầng và cầm dịch vụ.

## [3]. References:

### Tools:

- tcpdump
  - Display hex byte: `tcpdump -XX -i eth0`.
  - Store pcap file:
    - `sudo tcpdump -i eth0 -w capture.pcap`.
    - `tcpdump -i eth0 -w cap.pcap tcp port 3139`.

### Kiến thức:

- Setup firewall, iptables, proxy

  - proxy là gì và cách setup và tạo 1 proxy trên linux (code proxy sử dụng của chính mình hoặc thông qua modsecurity).
  - proxy là 1 đoạn code chạy nó trên server (có thể là code python).
  - write rule use wireshark filter byte character in payload attack (viết rule chặn payload tấn công sử dụng modsecurity (viết rule đơn giản trên 1 server linux)).

- iptables: sudo iptables -L
  - iptables -t nat -L
  - nếu dung iptables -L mà ko tắt được rule thì phải dùng câu lệnh nào
  - https://www.youtube.com/playlist?list=PLvadQtO-ihXt5k8XME2iv0cKpKhcYqe7i
  - https://github.com/kienle1819/kienletv/tree/main/iptables

- Code auto-tools lấy flag (run script attack) và auto-tools submite flag (send flag+token-team)
  - `Crontab`: https://viblo.asia/p/cron-job-la-gi-huong-dan-su-dung-cron-tab-E375zLo2ZGW
- Training nghiệp vụ blue, xin tools customize, học iptables

### link-github:

- `Overview setup`: https://cbsctf.ru/ad
- `simple-portforwarder`: https://github.com/Q5Ca/simple-portforwarder
- `Caronte is a tool to analyze the network flow`: https://github.com/eciavatta/caronte
- `Platform build A&D (Viettel build)`:
  - https://github.com/pomo-mondreganto/ForcAD
  - `Attack and Defense CTF Competitions`:
    - `C4T BuT S4D`: https://github.com/C4T-BuT-S4D
    - `FAUST-CTF`: https://faust.cs.fau.de/ctf/
    - https://github.com/TowerofHanoi/CTFsubmitter
    - `CTFd Jeopardy`: https://github.com/CTFd/CTFd
- `Network analysis tool for Attack Defence CTF | Runs exploits, fast.`: https://github.com/OpenAttackDefenseTools

- `Video`:

  - https://archive.conference.hitb.org/hitbsecconf2021sin/capture-the-flag/
  - https://www.youtube.com/watch?v=oMDBTvehzs8

- Tools management A&D CTF:

  - https://github.com/vidar-team/Cardinal
  - https://viblo.asia/p/phat-hien-xam-nhap-voi-splunk-OeVKB8MdlkW
  - proxy Golang push log lên splunk 
  - ...

- `User github played a&d`:

  - https://github.com/tuantv89/ASCIS2022_WEB_Final/tree/main
  - https://github.com/to016/CTFs/tree/main/SVATTT/2022/Final/V-Store

- `Kể chuyện đi thi`:
  - https://q5ca.github.io/ctf/SVATTT2019-final-ke-chuyen-di-thi-va-wu-hackemall-12-01-2019.html
  - https://shfsec.com/chung-toi-da-vo-dich-df-cyber-defense-2023-nhu-the-nao-attack-defense
  - https://hackmd.io/@mochinishimiya/Sypvli8rj
  - ...
