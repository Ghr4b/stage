FROM wazuh/wazuh-manager:4.7.2

COPY custom-tijeri.py /var/ossec/integrations/custom-tijeri
COPY entrypoint.sh /tijeri-wazuh-entrypoint.sh

RUN chown root:wazuh /var/ossec/integrations/custom-tijeri \
 && chmod 750 /var/ossec/integrations/custom-tijeri \
 && chmod 755 /tijeri-wazuh-entrypoint.sh \
 && command -v python3

ENTRYPOINT ["/tijeri-wazuh-entrypoint.sh"]
