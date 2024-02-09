{{/* Define the secrets */}}
{{- define "wazuh.secrets" -}}

{{- $fullName := (include "tc.v1.common.lib.chart.names.fullname" $) -}}
{{- $namespace := (include "tc.v1.common.lib.metadata.namespace" (dict "rootCtx" $ "objectData" . "caller" "Configmap")) -}}
{{- $fqdn := (include "tc.v1.common.lib.chart.names.fqdn" $) -}}
{{- $dashboardUrl := printf "%v.svc.cluster.local" $fqdn -}}
{{- $managerUrl := printf "%v-manager.%v.svc.cluster.local" $fullName $namespace -}}
{{- $indexerUrl := printf "%v-indexer.%v.svc.cluster.local" $fullName $namespace -}}
{{- $indexerPort := printf "%v" .Values.service.indexer.ports.indexer.port -}}
{{- $dashboardPort := printf "%v" .Values.service.main.ports.main.port -}}

{{/* Generate Root CA */}}
{{- $rootCA := genCA "root-ca" 3650 -}}

{{/* Generate and Store Admin Certificate */}}
{{- $adminCert := genSignedCert "admin" nil nil 3650 $rootCA -}}

{{/* Generate and Store Node Certificate */}}
{{- $nodeCert := genSignedCert $indexerUrl nil nil 3650 $rootCA -}}

{{/* Generate and Store Dashboard Certificate */}}
{{- $dashboardCert := genSignedCert "dashboard" nil nil 3650 $rootCA -}}

{{/* Generate and Store Filebeat Certificate */}}
{{- $filebeatCert := genSignedCert "filebeat" nil nil 3650 $rootCA -}}

secret:
  test:
    enabled: true
    data:
      fullName: {{ $fullName }}
      namespace: {{ $namespace }}
      fqdn: {{ $fqdn }}
      dashboardUrl: {{ $dashboardUrl }}
      managerUrl: {{ $managerUrl }}
      indexerUrl: {{ $indexerUrl }}

  root-ca:
    enabled: true
    type: kubernetes.io/tls
    data:
      tls.key: {{ $rootCA.Key | quote }}
      tls.crt: {{ $rootCA.Cert | quote }}

  admin-cert:
    enabled: true
    type: kubernetes.io/tls
    data:
      tls.key: {{ $adminCert.Key | quote }}
      tls.crt: {{ $adminCert.Cert | quote }}

  node-cert:
    enabled: true
    type: kubernetes.io/tls
    data:
      tls.key: {{ $nodeCert.Key | quote }}
      tls.crt: {{ $nodeCert.Cert | quote }}

  dashboard-cert:
    enabled: true
    type: kubernetes.io/tls
    data:
      tls.key: {{ $dashboardCert.Key | quote }}
      tls.crt: {{ $dashboardCert.Cert | quote }}

  filebeat-cert:
    enabled: true
    type: kubernetes.io/tls
    data:
      tls.key: {{ $filebeatCert.Key | quote }}
      tls.crt: {{ $filebeatCert.Cert | quote }}

configmap:
  indexer:
    enabled: true
    data:
      internal_users.yml: |
        ---
        # This is the internal user database
        # The hash value is a bcrypt hash and can be generated with plugin/tools/hash.sh

        _meta:
          type: "internalusers"
          config_version: 2

        # Define your internal users here

        ## Demo users

        admin:
          hash: "$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO"
          reserved: true
          backend_roles:
          - "admin"
          description: "Demo admin user"

        kibanaserver:
          hash: "$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H."
          reserved: true
          description: "Demo kibanaserver user"

        kibanaro:
          hash: "$2a$12$JJSXNfTowz7Uu5ttXfeYpeYE0arACvcwlPBStB1F.MI7f0U9Z4DGC"
          reserved: false
          backend_roles:
          - "kibanauser"
          - "readall"
          attributes:
            attribute1: "value1"
            attribute2: "value2"
            attribute3: "value3"
          description: "Demo kibanaro user"

        logstash:
          hash: "$2a$12$u1ShR4l4uBS3Uv59Pa2y5.1uQuZBrZtmNfqB3iM/.jL0XoV9sghS2"
          reserved: false
          backend_roles:
          - "logstash"
          description: "Demo logstash user"

        readall:
          hash: "$2a$12$ae4ycwzwvLtZxwZ82RmiEunBbIPiAmGZduBAjKN0TXdwQFtCwARz2"
          reserved: false
          backend_roles:
          - "readall"
          description: "Demo readall user"

        snapshotrestore:
          hash: "$2y$12$DpwmetHKwgYnorbgdvORCenv4NAK8cPUg8AI6pxLCuWf/ALc0.v7W"
          reserved: false
          backend_roles:
          - "snapshotrestore"
          description: "Demo snapshotrestore user"
      wazuh.indexer.yml: |
        network.host: "0.0.0.0"
        node.name: "{{ $indexerUrl }}"
        path.data: /var/lib/wazuh-indexer
        path.logs: /var/log/wazuh-indexer
        discovery.type: single-node
        http.port: 9200-9299
        transport.tcp.port: 9300-9399
        compatibility.override_main_response_version: true
        plugins.security.ssl.http.pemcert_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.pem
        plugins.security.ssl.http.pemkey_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.key
        plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
        plugins.security.ssl.transport.pemcert_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.pem
        plugins.security.ssl.transport.pemkey_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.key
        plugins.security.ssl.transport.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
        plugins.security.ssl.http.enabled: true
        plugins.security.ssl.transport.enforce_hostname_verification: false
        plugins.security.ssl.transport.resolve_hostname: false
        plugins.security.authcz.admin_dn:
        - "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
        plugins.security.check_snapshot_restore_write_privileges: true
        plugins.security.enable_snapshot_restore_privilege: true
        plugins.security.nodes_dn:
        - "CN={{ $indexerUrl }},OU=Wazuh,O=Wazuh,L=California,C=US"
        plugins.security.restapi.roles_enabled:
        - "all_access"
        - "security_rest_api_access"
        plugins.security.system_indices.enabled: true
        plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]
        plugins.security.allow_default_init_securityindex: true
        cluster.routing.allocation.disk.threshold_enabled: false
  dashboard:
    enabled: true
    data:
      wazuh.yml: |
        hosts:
        - 1513629884013:
            url: "https://{{ $managerUrl }}"
            port: 55000
            username: {{ .Values.wazuh.outposts.manager.username | quote }}
            password: {{ .Values.wazuh.outposts.manager.password | quote }}
            run_as: false
      opensearch_dashboards.yml: |
        server.host: 0.0.0.0
        server.port: 5601
        opensearch.hosts: "https://{{ $indexerUrl }}:{{ $indexerPort }}"
        opensearch.ssl.verificationMode: certificate
        opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
        opensearch_security.multitenancy.enabled: false
        opensearch_security.readonly_mode.roles: ["kibana_read_only"]
        server.ssl.enabled: true
        server.ssl.key: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
        server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
        opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
        uiSettings.overrides.defaultRoute: /app/wazuh
  manager:
    enabled: true
    data:
      wazuh_manager.conf: |
        <ossec_config>
          <global>
            <jsonout_output>yes</jsonout_output>
            <alerts_log>yes</alerts_log>
            <logall>no</logall>
            <logall_json>no</logall_json>
            <email_notification>no</email_notification>
            <smtp_server>smtp.example.wazuh.com</smtp_server>
            <email_from>wazuh@example.wazuh.com</email_from>
            <email_to>recipient@example.wazuh.com</email_to>
            <email_maxperhour>12</email_maxperhour>
            <email_log_source>alerts.log</email_log_source>
            <agents_disconnection_time>10m</agents_disconnection_time>
            <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
          </global>

          <alerts>
            <log_alert_level>3</log_alert_level>
            <email_alert_level>12</email_alert_level>
          </alerts>

          <!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
          <logging>
            <log_format>plain</log_format>
          </logging>

          <remote>
            <connection>secure</connection>
            <port>1514</port>
            <protocol>tcp</protocol>
            <queue_size>131072</queue_size>
          </remote>

          <!-- Policy monitoring -->
          <rootcheck>
            <disabled>no</disabled>
            <check_files>yes</check_files>
            <check_trojans>yes</check_trojans>
            <check_dev>yes</check_dev>
            <check_sys>yes</check_sys>
            <check_pids>yes</check_pids>
            <check_ports>yes</check_ports>
            <check_if>yes</check_if>

            <!-- Frequency that rootcheck is executed - every 12 hours -->
            <frequency>43200</frequency>

            <rootkit_files>etc/rootcheck/rootkit_files.txt</rootkit_files>
            <rootkit_trojans>etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>

            <skip_nfs>yes</skip_nfs>
          </rootcheck>

          <wodle name="cis-cat">
            <disabled>yes</disabled>
            <timeout>1800</timeout>
            <interval>1d</interval>
            <scan-on-start>yes</scan-on-start>

            <java_path>wodles/java</java_path>
            <ciscat_path>wodles/ciscat</ciscat_path>
          </wodle>

          <!-- Osquery integration -->
          <wodle name="osquery">
            <disabled>yes</disabled>
            <run_daemon>yes</run_daemon>
            <log_path>/var/log/osquery/osqueryd.results.log</log_path>
            <config_path>/etc/osquery/osquery.conf</config_path>
            <add_labels>yes</add_labels>
          </wodle>

          <!-- System inventory -->
          <wodle name="syscollector">
            <disabled>no</disabled>
            <interval>1h</interval>
            <scan_on_start>yes</scan_on_start>
            <hardware>yes</hardware>
            <os>yes</os>
            <network>yes</network>
            <packages>yes</packages>
            <ports all="no">yes</ports>
            <processes>yes</processes>

            <!-- Database synchronization settings -->
            <synchronization>
              <max_eps>10</max_eps>
            </synchronization>
          </wodle>

          <sca>
            <enabled>yes</enabled>
            <scan_on_start>yes</scan_on_start>
            <interval>12h</interval>
            <skip_nfs>yes</skip_nfs>
          </sca>

          <vulnerability-detector>
            <enabled>no</enabled>
            <interval>5m</interval>
            <min_full_scan_interval>6h</min_full_scan_interval>
            <run_on_start>yes</run_on_start>

            <!-- Ubuntu OS vulnerabilities -->
            <provider name="canonical">
              <enabled>no</enabled>
              <os>trusty</os>
              <os>xenial</os>
              <os>bionic</os>
              <os>focal</os>
              <os>jammy</os>
              <update_interval>1h</update_interval>
            </provider>

            <!-- Debian OS vulnerabilities -->
            <provider name="debian">
              <enabled>no</enabled>
              <os>buster</os>
              <os>bullseye</os>
              <os>bookworm</os>
              <update_interval>1h</update_interval>
            </provider>

            <!-- RedHat OS vulnerabilities -->
            <provider name="redhat">
              <enabled>no</enabled>
              <os>5</os>
              <os>6</os>
              <os>7</os>
              <os>8</os>
              <os>9</os>
              <update_interval>1h</update_interval>
            </provider>

            <!-- Amazon Linux OS vulnerabilities -->
            <provider name="alas">
              <enabled>no</enabled>
              <os>amazon-linux</os>
              <os>amazon-linux-2</os>
              <os>amazon-linux-2023</os>
              <update_interval>1h</update_interval>
            </provider>

            <!-- SUSE Linux Enterprise OS vulnerabilities -->
            <provider name="suse">
              <enabled>no</enabled>
              <os>11-server</os>
              <os>11-desktop</os>
              <os>12-server</os>
              <os>12-desktop</os>
              <os>15-server</os>
              <os>15-desktop</os>
              <update_interval>1h</update_interval>
            </provider>

            <!-- Arch OS vulnerabilities -->
            <provider name="arch">
              <enabled>no</enabled>
              <update_interval>1h</update_interval>
            </provider>

            <!-- Alma Linux OS vulnerabilities -->
            <provider name="almalinux">
              <enabled>no</enabled>
              <os>8</os>
              <os>9</os>
              <update_interval>1h</update_interval>
            </provider>

            <!-- Windows OS vulnerabilities -->
            <provider name="msu">
              <enabled>yes</enabled>
              <update_interval>1h</update_interval>
            </provider>

            <!-- Aggregate vulnerabilities -->
            <provider name="nvd">
              <enabled>yes</enabled>
              <update_interval>1h</update_interval>
            </provider>

          </vulnerability-detector>

          <!-- File integrity monitoring -->
          <syscheck>
            <disabled>no</disabled>

            <!-- Frequency that syscheck is executed default every 12 hours -->
            <frequency>43200</frequency>

            <scan_on_start>yes</scan_on_start>

            <!-- Generate alert when new file detected -->
            <alert_new_files>yes</alert_new_files>

            <!-- Don't ignore files that change more than 'frequency' times -->
            <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

            <!-- Directories to check  (perform all possible verifications) -->
            <directories>/etc,/usr/bin,/usr/sbin</directories>
            <directories>/bin,/sbin,/boot</directories>

            <!-- Files/directories to ignore -->
            <ignore>/etc/mtab</ignore>
            <ignore>/etc/hosts.deny</ignore>
            <ignore>/etc/mail/statistics</ignore>
            <ignore>/etc/random-seed</ignore>
            <ignore>/etc/random.seed</ignore>
            <ignore>/etc/adjtime</ignore>
            <ignore>/etc/httpd/logs</ignore>
            <ignore>/etc/utmpx</ignore>
            <ignore>/etc/wtmpx</ignore>
            <ignore>/etc/cups/certs</ignore>
            <ignore>/etc/dumpdates</ignore>
            <ignore>/etc/svc/volatile</ignore>

            <!-- File types to ignore -->
            <ignore type="sregex">.log$|.swp$</ignore>

            <!-- Check the file, but never compute the diff -->
            <nodiff>/etc/ssl/private.key</nodiff>

            <skip_nfs>yes</skip_nfs>
            <skip_dev>yes</skip_dev>
            <skip_proc>yes</skip_proc>
            <skip_sys>yes</skip_sys>

            <!-- Nice value for Syscheck process -->
            <process_priority>10</process_priority>

            <!-- Maximum output throughput -->
            <max_eps>100</max_eps>

            <!-- Database synchronization settings -->
            <synchronization>
              <enabled>yes</enabled>
              <interval>5m</interval>
              <max_interval>1h</max_interval>
              <max_eps>10</max_eps>
            </synchronization>
          </syscheck>

          <!-- Active response -->
          <global>
            <white_list>127.0.0.1</white_list>
            <white_list>^localhost.localdomain$</white_list>
          </global>

          <command>
            <name>disable-account</name>
            <executable>disable-account</executable>
            <timeout_allowed>yes</timeout_allowed>
          </command>

          <command>
            <name>restart-wazuh</name>
            <executable>restart-wazuh</executable>
          </command>

          <command>
            <name>firewall-drop</name>
            <executable>firewall-drop</executable>
            <timeout_allowed>yes</timeout_allowed>
          </command>

          <command>
            <name>host-deny</name>
            <executable>host-deny</executable>
            <timeout_allowed>yes</timeout_allowed>
          </command>

          <command>
            <name>route-null</name>
            <executable>route-null</executable>
            <timeout_allowed>yes</timeout_allowed>
          </command>

          <command>
            <name>win_route-null</name>
            <executable>route-null.exe</executable>
            <timeout_allowed>yes</timeout_allowed>
          </command>

          <command>
            <name>netsh</name>
            <executable>netsh.exe</executable>
            <timeout_allowed>yes</timeout_allowed>
          </command>

          <!--
          <active-response>
            active-response options here
          </active-response>
          -->

          <!-- Log analysis -->
          <localfile>
            <log_format>command</log_format>
            <command>df -P</command>
            <frequency>360</frequency>
          </localfile>

          <localfile>
            <log_format>full_command</log_format>
            <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
            <alias>netstat listening ports</alias>
            <frequency>360</frequency>
          </localfile>

          <localfile>
            <log_format>full_command</log_format>
            <command>last -n 20</command>
            <frequency>360</frequency>
          </localfile>

          <ruleset>
            <!-- Default ruleset -->
            <decoder_dir>ruleset/decoders</decoder_dir>
            <rule_dir>ruleset/rules</rule_dir>
            <rule_exclude>0215-policy_rules.xml</rule_exclude>
            <list>etc/lists/audit-keys</list>
            <list>etc/lists/amazon/aws-eventnames</list>
            <list>etc/lists/security-eventchannel</list>

            <!-- User-defined ruleset -->
            <decoder_dir>etc/decoders</decoder_dir>
            <rule_dir>etc/rules</rule_dir>
          </ruleset>

          <rule_test>
            <enabled>yes</enabled>
            <threads>1</threads>
            <max_sessions>64</max_sessions>
            <session_timeout>15m</session_timeout>
          </rule_test>

          <!-- Configuration for wazuh-authd -->
          <auth>
            <disabled>no</disabled>
            <port>1515</port>
            <use_source_ip>no</use_source_ip>
            <purge>yes</purge>
            <use_password>no</use_password>
            <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
            <!-- <ssl_agent_ca></ssl_agent_ca> -->
            <ssl_verify_host>no</ssl_verify_host>
            <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
            <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
            <ssl_auto_negotiate>no</ssl_auto_negotiate>
          </auth>

          <cluster>
            <name>wazuh</name>
            <node_name>node01</node_name>
            <node_type>master</node_type>
            <key>aa093264ef885029653eea20dfcf51ae</key>
            <port>1516</port>
            <bind_addr>0.0.0.0</bind_addr>
            <nodes>
                <node>wazuh.manager</node>
            </nodes>
            <hidden>no</hidden>
            <disabled>yes</disabled>
          </cluster>

        </ossec_config>

        <ossec_config>
          <localfile>
            <log_format>syslog</log_format>
            <location>/var/ossec/logs/active-responses.log</location>
          </localfile>

        </ossec_config>
{{- end -}}