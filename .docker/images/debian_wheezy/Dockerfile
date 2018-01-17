# vim:set ft=dockerfile:
FROM debian:wheezy

RUN echo 'deb-src http://http.debian.net/debian/ jessie main non-free contrib' >> /etc/apt/sources.list
RUN apt-get update

RUN apt-get install -y fakeroot build-essential devscripts g++-multilib libc6-dbg m4 libtool autoconf2.64 autogen gawk zlib1g-dev systemtap-sdt-dev flex gdb locales sharutils procps libantlr-java libffi-dev fastjar libmagic-dev zip libasound2-dev libxtst-dev libxt-dev libart-2.0-dev libcairo2-dev dejagnu chrpath quilt doxygen ghostscript texlive-latex-base xsltproc libxml2-utils docbook-xsl-ns binutils-multiarch gperf bison texinfo libecj-java libgtk2.0-dev libcloog-isl-dev libmpc-dev libmpfr-dev libgmp-dev realpath graphviz libcloog-isl-dev libmpc-dev
RUN cd /usr/src/ && apt-get source gcc-4.9/jessie

RUN mkdir /cc
COPY . /cc

RUN apt-get install -y python-software-properties
RUN apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
RUN add-apt-repository 'deb [arch=amd64,i386] http://fr.mirror.babylon.network/mariadb/repo/10.1/debian wheezy main'

RUN apt-get update && apt-get install -y cmake dos2unix mariadb-client

RUN mkdir /cc/build

RUN cd /cc/build \
    && cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/usr/local \
    && make \
    && make install

RUN chmod 755 /cc/.docker/run_test.sh
RUN dos2unix /cc/.docker/run_test.sh

CMD ["bash", "/cc/.docker/run_test.sh"]