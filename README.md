# Themis
Themis：a video-centric congestion control framework. It selects CC actions to optimize for QoE (rather than throughput) based on application-layer signals provided by
the client. 
The code is divided into two parts, one is for the server and the other is for the player.

## server

Before you run Themis server,you need to install nginx,php-fpm,llvm-12 clang-12,libelf-dev and php-redis.

To enable the server to obtain video playback information,you need:

* 1：cd /var/www/html/

* 2: rz -y playerServer.php

* 3: cd /nginx/sites-enabled

* 4: rz -y default

To effect the Themis,you need:

* 1: cd /root/linux/tools/testing/selftests/bpf/progs

* 2: rz -y bpf_bbr_new.c

* 3: cd ../

* 4: rz -y bpf_tcp_ca.c

* 5: make test_progs

* 6: ./test_progs

## player


When the preparatory work is completed,you can use player to watch videos :)
