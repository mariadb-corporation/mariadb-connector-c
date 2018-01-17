FROM centos:7.1.1503

RUN yum -y install epel-release
RUN yum repolist
RUN yum -y swap -- remove fakesystemd -- install systemd systemd-libs
RUN yum groupinstall -y "Development Tools"
RUN yum -y install dos2unix jsoncpp cmake3 openssl-devel

RUN mkdir /cc
COPY . /cc

RUN cp /cc/.docker/images/centos7.1/mariadb.repo /etc/yum.repos.d/

RUN yum -y install MariaDB-client

RUN mkdir /cc/build

RUN cd /cc/build \
    && cmake3 .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/usr/local \
    && make \
    && make install

RUN chmod 755 /cc/.docker/run_test3.sh
RUN dos2unix /cc/.docker/run_test3.sh

CMD ["bash", "/cc/.docker/run_test3.sh"]