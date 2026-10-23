FROM vulhub/phpmyadmin:4.8.1
RUN echo "deb http://archive.debian.org/debian stretch main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security stretch/updates main" >> /etc/apt/sources.list && \
    rm -f /etc/apt/sources.list.d/* && \
    apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y --allow-unauthenticated --no-install-recommends iproute2 && \
    rm -rf /var/lib/apt/lists/*
