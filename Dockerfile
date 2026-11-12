FROM httpd:2.4.71

# upgrade pulls in Debian security fixes released after the base image was built
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install --no-install-recommends -y \
    ca-certificates libapache2-mod-auth-openidc && \
    rm -rf /var/lib/apt/lists/*
