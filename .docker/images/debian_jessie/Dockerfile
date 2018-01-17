# vim:set ft=dockerfile:
FROM gcc:7

RUN mkdir /cc
COPY . /cc

RUN apt-get update && apt-get install -y cmake dos2unix mariadb-client

RUN mkdir /cc/build

RUN cd /cc/build \
    && cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/usr/local \
    && make \
    && make install

RUN chmod 755 /cc/.docker/run_test.sh
RUN dos2unix /cc/.docker/run_test.sh

CMD ["bash", "/cc/.docker/run_test.sh"]