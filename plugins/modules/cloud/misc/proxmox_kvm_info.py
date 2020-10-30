#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import re
import traceback

try:
    from proxmoxer import ProxmoxAPI
    HAS_PROXMOXER = True
except ImportError:
    PROXMOXER_IMP_ERR = traceback.format_exc()
    HAS_PROXMOXER = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback, missing_required_lib

class ProxmoxAnsible:
    def __init__(self, module):
        self.proxmox_api = self._connnect(module)
        # Test token validity
        try:
            self.proxmox_api.version.get()
        except Exception as e:
            module.fail_json(msg='%s' %e, exception=traceback.format_exc())

    def _connnect(self, module):
        api_host = module.params['api_host']
        api_user = module.params['api_user']
        api_password = module.params['api_password']
        api_token_id = module.params['api_token_id']
        api_token_secret = module.params['api_token_secret']
        validate_certs = module.params['validate_certs']

        auth_args = {'user': api_user}
        if api_password:
            auth_args['password'] = api_password
        else:
            auth_args['token_name'] = api_token_id
            auth_args['token_value'] = api_token_secret

        try:
            return ProxmoxAPI(api_host, verify_ssl=validate_certs, **auth_args)
        except Exception as e:
            module.fail_json(msg='%s' %e, exception=traceback.format_exc())

    def get_vms_by_cluster(self, **kwargs):
        vms = self.proxmox_api.cluster.resources.get(type='vm')
        return [ProxmoxVM(vm, self.proxmox_api, **kwargs) for vm in vms]

    def get_vms_by_node(self, node, **kwargs):
        vms = self.proxmox_api.cluster.resources.get(type='vm')
        return [ProxmoxVM(vm, self.proxmox_api, **kwargs) for vm in vms if vm['node'] == node]

    def get_vm_by_vmid(self, vmid, **kwargs):
        vms = self.proxmox_api.cluster.resources.get(type='vm')
        return [ProxmoxVM(vm, self.proxmox_api, **kwargs) for vm in vms if vm['vmid'] == int(vmid)]

    def get_vm_by_name(self, name, **kwargs):
        vms = self.proxmox_api.cluster.resources.get(type='vm')
        return [ProxmoxVM(vm, self.proxmox_api, **kwargs) for vm in vms if vm['name'] == name]

    def find_vms(self, name=None, node=None, vmid=None, **kwargs):
        if node:
            return self.get_vms_by_node(node, **kwargs)
        elif vmid:
            return self.get_vm_by_vmid(vmid, **kwargs)
        elif name:
            return self.get_vm_by_name(name, **kwargs)

        return self.get_vms_by_cluster(**kwargs)

    def vm_present(self, module):
        pass

    def clone(self, module):
        pass


class ProxmoxVM:
    def __init__(self, vm, proxmox_api, load_sections=[]):
        self.vm = vm
        self.proxmox_api = proxmox_api
        self.proxmox_api_vm = proxmox_api.nodes(vm['node']).qemu(vm['vmid'])

        sections = [s.upper() for s in load_sections]

        if any(item in ['CONFIG','ALL'] for item in sections):
            self.vm['config'] = self.get_config()

        if any(item in ['SNAPSHOTS', 'ALL'] for item in sections):
            self.vm['snapshots'] = self.get_snapshots()
        
        if any(item in ['FIREWALL', 'ALL'] for item in sections):
            self.vm['firewall'] = self.get_firewall_settings()
        
        if any(item in ['AGENT_NETWORK_INFO', 'ALL'] for item in sections):
            if 'agent' not in self.vm:
                self.vm['agent'] = {}

            self.vm['agent']['network'] = self.get_agent_network_info()
        
        if any(item in ['AGENT_OS_INFO', 'ALL'] for item in sections):
            if 'agent' not in self.vm:
                self.vm['agent'] = {}

            self.vm['agent']['os'] = self.get_agent_os_info()

    def get_config(self):
        return self.proxmox_api_vm.config.get()

    def get_snapshots(self):
        return self.proxmox_api_vm.snapshot.get()

    def get_firewall_settings(self):
        return self.proxmox_api_vm.firewall.get()

    def get_agent_network_info(self):
        try:
            return self.proxmox_api_vm.agent.create(command='network-get-interfaces')['result']
        except:
            return { 'error': 'Error collecting network information' }

    def get_agent_os_info(self):
        try:
            return self.proxmox_api_vm.agent.create(command='get-osinfo')['result']
        except:
            return { 'error': 'Error collecting os information' }

def proxmox_argument_spec():
    return dict(
        name = dict(
            type = 'str',
            default = None,
            api_name = 'name'),
        node = dict(
            type = 'str',
            default = None,
            api_name = 'node'),
        api_host = dict(
            required = True,
            fallback = (env_fallback, ['PROXMOX_HOST'])),
        api_user = dict(
            required = True,
            fallback = (env_fallback, ['PROXMOX_USER'])),
        api_password = dict(
            no_log = True,
            fallback = (env_fallback, ['PROXMOX_PASSWORD'])),
        api_token_id = dict(
            no_log = True),
        api_token_secret = dict(
            no_log = True),
        load_sections = dict(
            type = 'list',
            default = ['config']),
        type = dict(
            type = 'str',
            default = 'all',
            choices = ['all', 'vm', 'template']),
        validate_certs = dict(
            type = 'bool',
            default = True),
        vmid = dict(
            type = 'int',
            default = None,
            api_name = 'vmid'),
    )

def run_module():
    module_args = proxmox_argument_spec()

    module = AnsibleModule(
        argument_spec=module_args,
        mutually_exclusive=[('vmid', 'name', 'node')],
        required_one_of=[('api_password', 'api_token_id')],
        required_together=[('api_token_id', 'api_token_secret')],
        supports_check_mode=True
    )

    result = dict(
        changed=False
    )

    if not HAS_PROXMOXER:
        module.fail_json(msg=missing_required_lib('proxmoxer'), exception=PROXMOXER_IMP_ERR)

    name = module.params['name']
    node = module.params['node']
    api_host = module.params['api_host']
    api_password = module.params['api_password']
    api_user = module.params['api_user']
    vm_type = module.params['type']
    vmid = module.params['vmid']
    validate_certs = module.params['validate_certs']
    load_sections = module.params['load_sections']

    proxmox = ProxmoxAnsible(module)
    
    vms = proxmox.find_vms(name=name, node=node, vmid=vmid, load_sections=load_sections)

    result['virtual_machines'] = [vm.vm for vm in vms]

    if module.check_mode:
        module.exit_json(**result)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
