# PostgreSQL with TLS enabled on port 5432. Certs are baked into the image
# (configs/certs/modern) and ownership/perms fixed so the postgres user can
# read the private key - a bind-mounted key would keep host ownership and
# postgres would refuse to start. Modern TLS on a non-web port: the scanner
# must map 5432 AND probe it independently of any web ports.
FROM postgres:13-alpine

COPY certs/ /etc/ssl/pgsql/
RUN chown -R postgres:postgres /etc/ssl/pgsql \
    && chmod 600 /etc/ssl/pgsql/key.pem \
    && chmod 644 /etc/ssl/pgsql/cert.pem

CMD ["postgres", \
     "-c", "ssl=on", \
     "-c", "ssl_cert_file=/etc/ssl/pgsql/cert.pem", \
     "-c", "ssl_key_file=/etc/ssl/pgsql/key.pem"]