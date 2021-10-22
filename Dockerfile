FROM debian

RUN apt-get update && apt-get install wget sudo build-essential zlib1g-dev libssl-dev libpam0g-dev libselinux1-dev -y

RUN useradd --create-home --shell '/bin/bash' --comment 'Test user' 'test' && echo test:test | chpasswd

RUN mkdir /var/lib/sshd && chmod -R 700 /var/lib/sshd/ && chown -R root:sys /var/lib/sshd/ && useradd -r -U -d /var/lib/sshd/ -c "sshd privsep" -s /bin/false sshd

RUN wget -c https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-8.8p1.tar.gz && tar -xzf openssh-8.8p1.tar.gz \
  && cd openssh-8.8p1/ && sed -i '1s/^/#define DEBUG_KEXECDH 1 /' kex.h \
  && ./configure --with-md5-passwords --with-pam --with-selinux --with-privsep-path=/var/lib/sshd/ --sysconfdir=/etc/ssh \
  && make && make install

RUN ssh-keygen -A && mkdir -p /run/sshd

COPY sshd_config /etc/ssh/sshd_config

CMD /usr/local/sbin/sshd -D -e && while true; do sleep 1; done;

# run docker
# docker build . -t ssh_test && docker run -d -p 2222:22 --name ssh_test ssh_test && docker logs -f ssh_test
