Enable NGINX App Protect with NGINX Controller Application Delivery
==================================================
.. contents:: Table of Contents

Summary
==================================================
Use Case
###############
- **Security** -- Secure applications with customized WAF policies
- **Role Base Access Control** -- Delegate Reverse-Proxy configuration to DevOps and WAF policies to SecOps
- **Automation** -- Automate changes:
A) [SecOps] **Attach a WAF policy to an Application** -- A default WAF policy is applied, unless a specific WAF policy is set by SecOps
B) [DevOps] **Deploy an Application** -- DevOps deploy Applications, regardless of WAF policies set
C) [SecOps] **Update WAF policies** -- SecOps update WAF policies
D) [DevOps] **Remove an Application**
E) [SecOps] **Detach a WAF policy from an Application**

Benefit
###############
- **Security** -- protect and managed False Positive per Application
- **Role Base Access Control** -- Clear responsibility between DevOps and SecOps
- **Automation** -- Autonomous deployment operations between DevOps and SecOps

Benefit
###############
- **Granularity** -- WAF policy per FQDN (server_name block), not per PATH (location block)
- **Log** -- Logs are stored locally or/and sent to a remote syslog server, not sent to NGINX Controller

Architecture
###############
.. figure:: _figure/Architecture_INBOUND_WAF.png

Ecosystem
*********************
- NGINX+
- NGINX App Protect
- NGINX Controller
- Ansible Tower
- Consul by Hashicorp
- GitHub webhook

Demo
###############
- Automate an Application deployment
.. raw:: html

    <a href="http://www.youtube.com/watch?v=p1rfhssaE_U"><img src="http://img.youtube.com/vi/p1rfhssaE_U/0.jpg" width="600" height="400" title="Automate an Application deployment" alt="Automate an Application deployment"></a>

Pre-requisites
==============

Kibana
##############
`install guide <https://github.com/464d41/f5-waf-elk-dashboards>`_

NGINX Controller
##############
`install guide <https://github.com/MattDierick/docker-nginx-controller>`_

Consul by Hashicorp
###################
`install guide <https://github.com/nergalex/f5-sslo-category#consul>`_

Ansible Tower
##############

Azure azure_preview_modules
***************************
This role is the most complete and includes all the latest Azure modules. The update and bug fix are done in a more timely manner than official Ansible release.
If you use Ansible for Azure resource provisioning purpose, you're strongly encouraged to install this role.
Follow `install guide <https://github.com/Azure/azure_preview_modules>`_

.. code:: bash
    $ sudo ansible-galaxy install azure.azure_preview_modules
    $ sudo /var/lib/awx/venv/my_env/bin/pip install -U -r /etc/ansible/roles/azure.azure_preview_modules/files/requirements-azure.txt
    $ sudo /var/lib/awx/venv/my_env/bin/pip show azure-mgmt-compute

If ``azure-mgmt-compute`` < ``10.0.0`` then use last update from azure_preview_modules repo and not from Galaxy.
``/etc/ansible/roles/`` is an example of an Tower installation where ``roles`` are located.

.. code:: bash
    $ sudo cd /etc/ansible/roles/
    $ sudo git clone https://github.com/Azure/azure_preview_modules.git
    $ sudo /var/lib/awx/venv/my_env/bin/pip install -r /etc/ansible/roles/azure.azure_preview_modules/files/requirements-azure.txt
    $ sudo vi /etc/ansible/roles/azure.azure_preview_modules/defaults/main.yml
        skip_azure_sdk: false

Custom module for azure_preview_modules
***************************************
Copy modules below to ``/etc/ansible/roles/azure.azure_preview_modules/library/``:

- ``azure_rm_networkinterface_vmss_info.py``
- ``azure_rm_virtualmachinescalesetinstance_info.py``

Consul
***************************
.. code:: bash
    $ sudo /var/lib/awx/venv/my_env/bin/pip install python-consul

VMSS credential
***************
Create custom credential `cred_NGINX` to manage access to VMs in VMSS

=====================================================   =============================================       =============================================   =============================================   =============================================
REDENTIAL TYPE                                            USERNAME                                           SSH PRIVATE KEY                                        SIGNED SSH CERTIFICATE                                        PRIVILEGE ESCALATION METHOD
=====================================================   =============================================       =============================================   =============================================   =============================================
``Machine``                                             ``my_VM_admin_user``                                ``my_VM_admin_user_key``                        ``my_VM_admin_user_CRT``                        ``sudo``
=====================================================   =============================================       =============================================   =============================================   =============================================

Role structure
**************
- Deployment is based on ``workflow template``. Example: ``workflow template``=``wf-create_create_edge_security_inbound`` ;
- A ``workflow template`` includes multiple ``job template``. Example: ``job template``=``poc-azure_create_hub_edge_security_inbound``
- A ``job template`` have an associated ``playbook``. Example: ``playbook``=``playbooks/poc-azure.yaml``
- A ``playbook`` launch a ``play`` in a ``role``. Example: ``role``=``poc-azure``

.. code:: yaml

    - hosts: localhost
      gather_facts: no
      roles:
        - role: poc-azure

- A ``play`` is an ``extra variable`` named ``activity`` and set in each ``job template``. Example: ``create_hub_edge_security_inbound``
- The specified ``play`` (or ``activity``) is launched by the ``main.yaml`` task located in the role ``tasks/main.yaml``

.. code:: yaml

    - name: Run specified activity
      include_tasks: "{{ activity }}.yaml"
      when: activity is defined

- The specified ``play`` contains ``tasks`` to execute. Example: play=``create_hub_edge_security_inbound.yaml``

A) [SecOps] Attach a WAF policy to an Application
==================================================
Create and launch a job template ``poc-consul_nap-server_name_create``:

=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
Job template                                                    objective                                           playbook                                        activity                                        inventory                                       limit                                           credential
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
``poc-consul_nap-server_name_create``                           Update Consul key/value store                       ``playbooks/poc-consul_agent.yaml``             ``nap-server_name_create``                      ``localhost``
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================

==============================================  =============================================   ================================================================================================================================================================================================================
Extra variable                                  Description                                     Example
==============================================  =============================================   ================================================================================================================================================================================================================
``extra_consul_path_source_of_truth``           Consul key path                                 ``poc_f5/inbound/nap``
``extra_consul_agent_ip``                       Consul server IP                                ``10.100.0.60``
``extra_consul_agent_port``                     Consul server port                              ``8500``
``extra_consul_agent_scheme``                   Consul server scheme                            ``http``
``extra_consul_datacenter``                     Consul datacenter                               ``Inbound``
``extra_server_name``                           FQDN = NGINX CTRL Gateway::Hostname record      ``my-app.f5cloudbuilder.dev``
``extra_server_properties``                     WAF policy properties                           ``{'waf_policy': 'secure_high-server_bundle1.json', 'enable': 'on'}``
==============================================  =============================================   ================================================================================================================================================================================================================

B) [DevOps] Deploy an Application
==================================================
Create and launch a workflow template ``wf-create-app_inbound_nginx_controller_nap`` that includes those Job templates in this order:

=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
Job template                                                    objective                                           playbook                                        activity                                        inventory                                       limit                                           credential
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
``poc-nginx_controller-login``                                  GET authentication token                            ``playbooks/poc-nginx_controller.yaml``         ``login``                                       ``localhost``                                   ``localhost``
``poc-nginx_controller-create_environment``                     Create an environment                               ``playbooks/poc-nginx_controller.yaml``         ``create_environment``                          ``localhost``                                   ``localhost``
``poc-azure_get-vmss-facts-credential_set``                     Get info of NGINX VMSS                              ``playbooks/poc-azure.yaml``                    ``get-vmss-facts``                              ``my_project``                                  ``localhost``                                   ``my_azure_credential``
``poc-nginx_controller-create_gw_app_component_vmss_north``     Create App on North GW / WAF                        ``playbooks/poc-nginx_controller.yaml``         ``create_gw_app_component_vmss_north``          `localhost``                                    ``localhost``
``wf-nginx_managed-nap_update_waf_policy``                      Apply WAF policies                                  ``workflow`` see use case (C)
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================

==============================================  =============================================   ================================================================================================================================================================================================================
Extra variable                                  Description                                     Example
==============================================  =============================================   ================================================================================================================================================================================================================
``extra_project_name``                          Project name                                    ``CloudBuilderf5``
``extra_vmss_name``                             NGINX VMSS name                                 ``myWAFcluster``
``extra_platform_name``                         Consul DataCenter name                          ``Inbound``
``extra_app_protect_monitor_ip``                Remote syslog server IP (Kibana, SIEM...)       ``10.0.0.20``
``extra_app_protect_monitor_port``              Remote syslog server port (Kibana, SIEM...)     ``5144``
``extra_nap_repo``                              WAF policy repo managed by SecOps               ``https://github.com/nergalex/f5-nap-policies.git``
``extra_consul_path_source_of_truth``           Consul key path                                 ``poc_f5/inbound/nap``
``extra_consul_path_lookup``                    Consul key | server names to protect            ``server_names``
``extra_consul_agent_ip``                       Consul server IP                                ``10.100.0.60``
``extra_consul_agent_port``                     Consul server port                              ``8500``
``extra_consul_agent_scheme``                   Consul server scheme                            ``http``
``extra_consul_datacenter``                     Consul datacenter                               ``Inbound``
``extra_app``                                   App specification                               see below
``extra_nginx_controller_ip``                                                                   ``10.0.0.38``
``extra_nginx_controller_password``                                                             ``Cha4ngMe!``
``extra_nginx_controller_username``                                                             ``admin@acme.com``
==============================================  =============================================   ================================================================================================================================================================================================================

``extra_app`` structure, also stored as is in Consul:

.. code:: yaml

    extra_app:
      components:
        - name: north
          type: adc
          uri: /
          workloads:
            - 'http://10.12.1.4:81'
      domain: f5app.dev
      environment: PROD
      name: webmap
      tls:
        crt: "-----BEGIN CERTIFICATE-----\r\n...\r\n...\r\n-----END CERTIFICATE-----"
        key: "-----BEGIN RSA PRIVATE KEY-----\r\n...-----END RSA PRIVATE KEY-----"

C) [SecOps] Update WAF policies
==================================================
Workflow
##############
Create and launch a workflow template ``wf-nginx_managed-nap_update_waf_policy`` that includes those Job templates in this order:

=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
Job template                                                    objective                                           playbook                                        activity                                        inventory                                       limit                                           credential
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
``poc-nginx_controller-login``                                  GET authentication token                            ``playbooks/poc-nginx_controller.yaml``         ``login``                                       ``localhost``                                   ``localhost``
``poc-nginx_controller-create_environment``                     Create an environment                               ``playbooks/poc-nginx_controller.yaml``         ``create_environment``                          ``localhost``                                   ``localhost``
``poc-azure_get-vmss-facts-credential_set``                     Get info of NGINX VMSS                              ``playbooks/poc-azure.yaml``                    ``get-vmss-facts``                              ``my_project``                                  ``localhost``                                   ``my_azure_credential``
``poc-nginx_controller-create_gw_app_component_vmss_north``     Create App on North GW / WAF                        ``playbooks/poc-nginx_controller.yaml``         ``create_gw_app_component_vmss_north``          `localhost``                                    ``localhost``
``wf-nginx_managed-nap_update_waf_policy``                      Apply WAF policies                                  ``workflow`` see use case (C)
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================

==============================================  =============================================   ================================================================================================================================================================================================================
Extra variable                                  Description                                     Example
==============================================  =============================================   ================================================================================================================================================================================================================
``extra_vmss_name``                             NGINX VMSS name                                 ``myWAFcluster``
``extra_platform_name``                         Consul DataCenter name                          ``Inbound``
``extra_app_protect_monitor_ip``                Remote syslog server IP (Kibana, SIEM...)       ``10.0.0.20``
``extra_app_protect_monitor_port``              Remote syslog server port (Kibana, SIEM...)     ``5144``
``extra_nap_repo``                              WAF policy repo managed by SecOps               ``https://github.com/nergalex/f5-nap-policies.git``
``extra_consul_path_source_of_truth``           Consul key path                                 ``poc_f5/inbound/nap``
``extra_consul_path_lookup``                    Consul key | server names to protect            ``server_names``
``extra_consul_agent_ip``                       Consul server IP                                ``10.100.0.60``
``extra_consul_agent_port``                     Consul server port                              ``8500``
``extra_consul_agent_scheme``                   Consul server scheme                            ``http``
``extra_consul_datacenter``                     Consul datacenter                               ``Inbound``
``extra_app``                                   App specification                               see below
==============================================  =============================================   ================================================================================================================================================================================================================

Webhook
##############
`configuration guide <https://docs.ansible.com/ansible-tower/latest/html/userguide/webhooks.html#github-webhook-setup>`_

E) [SecOps] Attach a WAF policy to an Application
==================================================
Create and launch a job template ``poc-consul_nap-server_name_delete``:

=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
Job template                                                    objective                                           playbook                                        activity                                        inventory                                       limit                                           credential
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
``poc-consul_nap-server_name_delete``                           Remove Consul key/value store                       ``playbooks/poc-consul_agent.yaml``             ``nap-server_name_delete``                      ``localhost``
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================

==============================================  =============================================   ================================================================================================================================================================================================================
Extra variable                                  Description                                     Example
==============================================  =============================================   ================================================================================================================================================================================================================
``extra_consul_path_source_of_truth``           Consul key path                                 ``poc_f5/inbound/nap``
``extra_consul_agent_ip``                       Consul server IP                                ``10.100.0.60``
``extra_consul_agent_port``                     Consul server port                              ``8500``
``extra_consul_agent_scheme``                   Consul server scheme                            ``http``
``extra_consul_datacenter``                     Consul datacenter                               ``Inbound``
``extra_server_name``                           FQDN = NGINX CTRL Gateway::Hostname record      ``my-app.f5cloudbuilder.dev``
``extra_server_properties``                     WAF policy properties                           ``{'waf_policy': 'secure_high-server_bundle1.json', 'enable': 'on'}``
==============================================  =============================================   ================================================================================================================================================================================================================

