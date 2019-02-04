# Copyright 2017 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`local_config_util' --- library functions for SCION topology generator
===========================================================================
"""

# This library file is created in order to use the functions from
# services such as scion-coord, without having to run the whole
# scion-web instance on that machine.

# Stdlib
import configparser
import json
import os
import yaml
import toml
from collections import defaultdict
from string import Template

# SCION
from lib.crypto.asymcrypto import (
    get_core_sig_key_file_path,
    get_enc_key_file_path,
    get_sig_key_file_path,
)
from lib.crypto.certificate_chain import get_cert_chain_file_path
from lib.crypto.trc import get_trc_file_path
from lib.crypto.util import (
    get_ca_cert_file_path,
    get_ca_private_key_file_path,
    get_offline_key_file_path,
    get_online_key_file_path,
    get_master_key_file_path,
    MASTER_KEY_0,
    MASTER_KEY_1,
)
from lib.defines import (
    AS_CONF_FILE,
    GEN_PATH,
    PROJECT_ROOT,
    PROM_FILE,
    PATH_POLICY_FILE,
    SCIOND_API_SOCKDIR
)
from lib.util import (
    copy_file,
    read_file,
    write_file,
)
from topology.common import srv_iter
from topology.generator import DEFAULT_PATH_POLICY_FILE
from topology.supervisor import SupervisorGenArgs, SupervisorGenerator
from topology.go import GoGenerator, GoGenArgs
from topology.zk import ZKGenArgs, ZKGenerator

TYPES_TO_EXECUTABLES = {
    'router': 'border',
    'beacon_server': 'beacon_server',
    'path_server': 'path_srv',
    'certificate_server': 'cert_srv',
}

TYPES_TO_KEYS = {
    'beacon_server': 'BeaconService',
    'certificate_server': 'CertificateService',
    'router': 'BorderRouters',
    'path_server': 'PathService',
}

PROM_DIR = "prometheus"

TARGET_FILES = {
    "BorderRouters": "br.yml",
    "BeaconService": "bs.yml",
    "CertificateService": "cs.yml",
    "PathService": "ps.yml",
}

JOB_NAMES = {
    "BorderRouters": "BR",
    "BeaconService": "BS",
    "CertificateService": "CS",
    "PathService": "PS",
}

#: Default SCION Prometheus port offset
PROM_PORT_OFFSET = 1000

class dict_to_namedtuple:
    """Similarly to namedtuple, but initialized directly with the dictionary"""
    def __init__(self, d=None):
        if d:
            for k,v in d.items():
                setattr(self, k, v)

def isdas_str(isd_as):
    return isd_as.file_fmt() if 'file_fmt' in dir(isd_as) else str(isd_as)

def isd_str(isd_as):
    return isd_as.isd_str() if 'isd_str' in dir(isd_as) else isd_as[0]

def as_str(isd_as):
    return isd_as.as_file_fmt() if 'as_file_fmt' in dir(isd_as) else isd_as[1]


class ASCredential(object):
    """
    A class to keep the credentials of the SCION ASes.
    """
    def __init__(self, certificate, trc, keys, core_keys=None):
        self.certificate = certificate
        self.trc = trc
        self.keys = keys
        self.core_keys = core_keys

def nested_dicts_update(source, replacement):
    '''the result contains the union set of keys from source and replacement,
       also in nested dicts'''
    for k, v in replacement.items():
        if k in source.keys() and isinstance(v, dict):
            source[k] = nested_dicts_update(source[k], v)
        else:
            source[k] = v
    return source


def write_dispatcher_config(local_gen_path):
    """
    Creates the supervisord and zlog files for the dispatcher and writes
    them into the dispatcher folder.
    :param str local_gen_path: the location to create the dispatcher folder in.
    """
    disp_folder_path = os.path.join(local_gen_path, 'dispatcher')
    if not os.path.exists(disp_folder_path):
        os.makedirs(disp_folder_path)
    disp_supervisord_conf = prep_dispatcher_supervisord_conf()
    write_supervisord_config(disp_supervisord_conf, disp_folder_path)
    write_zlog_file('dispatcher', 'dispatcher', disp_folder_path)


def write_overlay_config(local_gen_path):
    overlay_file_path = os.path.join(local_gen_path, 'overlay')
    if not os.path.exists(overlay_file_path):
        write_file(overlay_file_path, 'UDP/IPv4')


def prep_supervisord_conf(instance_dict, executable_name, service_type, instance_name, isd_as):
    """
    Prepares the supervisord configuration for the infrastructure elements
    and returns it as a ConfigParser object.
    :param dict instance_dict: topology information of the given instance.
    :param str executable_name: the name of the executable.
    :param str service_type: the type of the service (e.g. beacon_server).
    :param str instance_name: the instance of the service (e.g. br1-8-1).
    :param ISD_AS isd_as: the ISD-AS the service belongs to.
    :returns: supervisord configuration as a ConfigParser object
    :rtype: ConfigParser
    """
    ISDAS = isdas_str(isd_as)
    if not instance_dict:
        cmd = 'bash -c \'exec "bin/sciond" "-config" "{elem_dir}/sciond.toml" &>logs/{instance}.OUT\'' \
            .format(elem_dir=get_elem_dir(GEN_PATH, isd_as, "endhost"), instance=instance_name)
        env = 'PYTHONPATH=python/:.,TZ=UTC'
    else:
        env_tmpl = 'PYTHONPATH=python/:.,TZ=UTC,ZLOG_CFG="%s/%s.zlog.conf"'
        env = env_tmpl % (get_elem_dir(GEN_PATH, isd_as, instance_name),
                          instance_name)
        IP, port = _prom_addr_of_element(instance_dict)
        prom_addr = "[%s]:%s" % (IP, port)
        if service_type == 'router':  # go router
            env += ',GODEBUG="cgocheck=0"'
            cmd = ('bash -c \'exec "bin/%s" "-id=%s" "-confd=%s" "-log.age=2" "-prom=%s" &>logs/%s.OUT\'') % (
                executable_name, instance_name, get_elem_dir(GEN_PATH, isd_as, instance_name),
                prom_addr, instance_name)
        elif service_type == 'certificate_server': # go certificate server
            env += ',SCIOND_PATH="/run/shm/sciond/default.sock"'
            cmd = 'bash -c \'exec "bin/{exe}" "-config" "{elem_dir}/csconfig.toml" &>logs/{instance}.OUT\'' \
                    .format(exe=executable_name, elem_dir=get_elem_dir(GEN_PATH, isd_as, instance_name),
                    instance=instance_name)
        elif service_type == 'path_server': # go path server
            cmd = 'bash -c \'exec "bin/{exe}" "-config" "{elem_dir}/psconfig.toml" &>logs/{instance}.OUT\'' \
                .format(exe=executable_name, elem_dir=get_elem_dir(GEN_PATH, isd_as, instance_name),
                instance=instance_name)
        else:  # other infrastructure elements, python
            cmd = ('bash -c \'exec "python/bin/{exe}" "--prom" "{prom}" "--sciond_path" '
                '"/run/shm/sciond/default.sock" "{instance}" "{elem_dir}" &>logs/{instance}.OUT\'') \
                .format(exe=executable_name,prom=prom_addr, instance=instance_name, 
                        elem_dir=get_elem_dir(GEN_PATH, isd_as, instance_name))
    config = configparser.ConfigParser()
    config['program:' + instance_name] = {
        'autostart': 'false',
        'autorestart': 'true',
        'environment': env,
        'stdout_logfile': 'NONE',
        'stderr_logfile': 'NONE',
        'startretries': '0',
        'startsecs': '5',
        'priority': '100',
        'command':  cmd
    }
    return config


def generate_zk_docker_config(tp, isd_as, local_gen_path, simple_conf_mode):
    """
    Generates Zookeeper configuration files for Zookeeper instances of an AS.
    :param dict tp: the topology of the AS provided as a dict of dicts.
    :param ISD_AS isd_as: ISD-AS for which the ZK config will be written.
    :param str local_gen_path: The gen path of scion-web.
    """
    zk_gen = ZKGenerator(ZKGenArgs(dict_to_namedtuple({'in_docker': False,
                         'output_dir': local_gen_path}), {isd_as: tp}))
    zk_gen.generate()


def get_elem_dir(path, isd_as, elem_id):
    """
    Generates and returns the directory of a SCION element.
    :param str path: Relative or absolute path.
    :param ISD_AS isd_as: ISD-AS to which the element belongs.
    :param elem_id: The name of the instance.
    :returns: The directory of the instance.
    :rtype: string
    """
    ISD = isd_str(isd_as)
    AS = as_str(isd_as)
    return "%s/ISD%s/AS%s/%s" % (path, ISD, AS, elem_id)


def prep_dispatcher_supervisord_conf():
    """
    Prepares the supervisord configuration for dispatcher.
    :returns: supervisord configuration as a ConfigParser object
    :rtype: ConfigParser
    """
    config = configparser.ConfigParser()
    env = 'PYTHONPATH=python:.,ZLOG_CFG="gen/dispatcher/dispatcher.zlog.conf"'
    cmd = """bash -c 'exec bin/dispatcher &>logs/dispatcher.OUT'"""
    config['program:dispatcher'] = {
        'autostart': 'false',
        'autorestart': 'true',
        'environment': env,
        'stdout_logfile': 'NONE',
        'stderr_logfile': 'NONE',
        'startretries': '0',
        'startsecs': '1',
        'priority': '50',
        'command':  cmd
    }
    return config


def write_topology_file(tp, type_key, instance_path):
    """
    Writes the topology file into the instance's location.
    :param dict tp: the topology as a dict of dicts.
    :param str type_key: key to describe service type.
    :param instance_path: the folder to write the file into.
    """
    path = os.path.join(instance_path, 'topology.json')
    with open(path, 'w') as file:
        json.dump(tp, file, indent=2)


def write_zlog_file(service_type, instance_name, instance_path):
    """
    Creates and writes the zlog configuration file for the given element.
    :param str service_type: the type of the service (e.g. beacon_server).
    :param str instance_name: the instance of the service (e.g. br1-8-1).
    """
    tmpl = Template(read_file(os.path.join(PROJECT_ROOT,
                                           "topology/zlog.tmpl")))
    cfg = os.path.join(instance_path, "%s.zlog.conf" % instance_name)
    write_file(cfg, tmpl.substitute(name=service_type,
                                    elem=instance_name))


def write_supervisord_config(config, instance_path):
    """
    Writes the given supervisord config into the provided location.
    :param ConfigParser config: supervisord configuration to write.
    :param instance_path: the folder to write the config into.
    """
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
    conf_file_path = os.path.join(instance_path, 'supervisord.conf')
    with open(conf_file_path, 'w') as configfile:
        config.write(configfile)


def write_certs_trc_keys(isd_as, as_obj, instance_path):
    """
    Writes the certificate and the keys for the given service
    instance of the given AS.
    :param ISD_AS isd_as: ISD the AS belongs to.
    :param obj as_obj: An object that stores crypto information for AS
    :param str instance_path: Location (in the file system) to write
    the configuration into.
    """
    # write keys
    cert_version = json.loads(as_obj.certificate)['0']['Version']
    trc_version = json.loads(as_obj.trc)['Version']
    as_key_path = {
        'cert': get_cert_chain_file_path(instance_path, isd_as, cert_version),
        'trc': get_trc_file_path(instance_path, isd_as[0], trc_version),
        'enc_key': get_enc_key_file_path(instance_path),
        'sig_key': get_sig_key_file_path(instance_path),
        'master0_as_key': get_master_key_file_path(instance_path, MASTER_KEY_0),
        'master1_as_key': get_master_key_file_path(instance_path, MASTER_KEY_1),
    }
    core_key_path = {
        'core_sig_key': get_core_sig_key_file_path(instance_path),
        'online_key': get_online_key_file_path(instance_path),
        'offline_key': get_offline_key_file_path(instance_path),
    }
    for key, path in as_key_path.items():
        if key == 'cert': # write certificates
            write_file(path, as_obj.certificate)
        elif key == 'trc': # write trc
            write_file(path, as_obj.trc)
        else: # write keys
            write_file(path, as_obj.keys[key])
    if as_obj.core_keys:
        for key, path in core_key_path.items():
            write_file(path, as_obj.core_keys[key])


def write_as_conf_and_path_policy(isd_as, as_obj, instance_path):
    """
    Writes AS configuration (i.e. as.yml) and path policy files.
    :param ISD_AS isd_as: ISD-AS for which the config will be written.
    :param obj as_obj: An object that stores crypto information for AS
    :param str instance_path: Location (in the file system) to write
    the configuration into.
    """
    conf = {
        # 'MasterASKey': as_obj.keys['master_as_key'],
        'RegisterTime': 5,
        'PropagateTime': 5,
        'CertChainVersion': 0,
        'RegisterPath': True,
        'PathSegmentTTL': 21600,
    }
    conf_file = os.path.join(instance_path, AS_CONF_FILE)
    write_file(conf_file, yaml.dump(conf, default_flow_style=False))
    path_policy_file = os.path.join(PROJECT_ROOT, DEFAULT_PATH_POLICY_FILE)
    copy_file(path_policy_file, os.path.join(instance_path, PATH_POLICY_FILE))

def write_toml_files(tp, ia):
    def replace(filename, replacement):
        '''Replace the toml dictionary in filename with the replacement dict'''
        with open(filename, 'r') as f:
            d = toml.load(f)
        nested_dicts_update(d, replacement)
        with open(filename, 'w') as f:
            toml.dump(d, f)

    used_prometheus_ports = set()
    def prom_params(elem):
        IP, port = _prom_addr_of_element(elem)
        if port in used_prometheus_ports:
            raise Exception('Duplicated Prometheus port {} found. The list of used ports is {}'.format(port, list(used_prometheus_ports)))
        used_prometheus_ports.add(port)
        return IP, port

    args = GoGenArgs(dict_to_namedtuple({'docker': False, 'trace': False,
                    'output_dir': GEN_PATH}), {ia: tp})
    go_gen = GoGenerator(args)

    go_gen.generate_sciond()
    IP, port = prom_params(None)
    filename = os.path.join(get_elem_dir(GEN_PATH, ia, 'endhost'), 'sciond.toml')
    replace(filename, {'sd': {'Reliable': os.path.join(SCIOND_API_SOCKDIR, 'default.sock'),
                                  'Unix': os.path.join(SCIOND_API_SOCKDIR, 'default.unix')},
                       'metrics': {'Prometheus': '{}:{}'.format(IP, port)}
                      })
    go_gen.generate_cs()
    IP, port = prom_params(next(iter(tp['CertificateService'].values())))
    filename = os.path.join(get_elem_dir(GEN_PATH, ia, next(iter(tp['CertificateService'].keys()))), 'csconfig.toml')
    replace(filename, {'sd_client': {'Path': os.path.join(SCIOND_API_SOCKDIR, 'default.sock')},
                        'metrics': {'Prometheus': '{}:{}'.format(IP,port)}
                      })
    go_gen.generate_ps()
    IP, port = prom_params(next(iter(tp['PathService'].values())))
    filename = os.path.join(get_elem_dir(GEN_PATH, ia, next(iter(tp['PathService'].keys()))), 'psconfig.toml')
    replace(filename, {'metrics': {'Prometheus': '{}:{}'.format(IP, port)}})

def generate_sciond_config(isd_as, as_obj, topo_dicts, gen_path=GEN_PATH):
    """
    Writes the endhost folder into the given location.
    :param ISD_AS isd_as: ISD the AS belongs to.
    :param obj as_obj: An object that stores crypto information for AS
    :param dict topo_dicts: the topology as a dict of dicts.
    :param str gen_path: the target location for a gen folder.
    """
    executable_name = "sciond"
    ISD = isd_str(isd_as)
    AS = as_str(isd_as)
    ISDAS = isdas_str(isd_as)
    instance_name = "sd%s" % ISDAS
    service_type = "endhost"
    instance_path = get_elem_dir(gen_path, isd_as, service_type)
    processes = []
    for svc_type in ["BorderRouters", "BeaconService",
                     "CertificateService", "PathService"]:
        if svc_type not in topo_dicts:
            continue
        for elem_id, elem in topo_dicts[svc_type].items():
            processes.append(elem_id)
    processes.append(instance_name)
    config = prep_supervisord_conf(None, executable_name, service_type, instance_name, isd_as)
    config['group:' + "as%s" % ISDAS] = {'programs': ",".join(processes)}
    write_certs_trc_keys(isd_as, as_obj, instance_path)
    write_as_conf_and_path_policy(isd_as, as_obj, instance_path)
    write_supervisord_config(config, os.path.join(gen_path, "ISD%s" % ISD, "AS%s" % AS))
    write_topology_file(topo_dicts, None, instance_path)


def generate_prom_config(isd_as, topo_dicts, gen_path=GEN_PATH):
    """
    """
    config_dict = defaultdict(list)
    for svc_type in ["BeaconService", "CertificateService", "PathService", "BorderRouters"]:
        if svc_type not in topo_dicts:
            continue
        for elem_id, elem in topo_dicts[svc_type].items():
            config_dict[svc_type].append('[{}]:{}'.format(*_prom_addr_of_element(elem)))
    _write_prom_files(isd_as, config_dict, gen_path)


def _write_prom_files(isd_as, config_dict, gen_path=GEN_PATH):
    ISD = isd_str(isd_as)
    AS = as_str(isd_as)
    base = os.path.join(gen_path, 'ISD%s' % ISD, 'AS%s' % AS)
    as_local_targets_path = {}
    targets_paths = defaultdict(list)
    for ele_type, target_list in config_dict.items():
        targets_path = os.path.join(base, PROM_DIR, TARGET_FILES[ele_type])
        target_config = [{'targets': target_list}]
        write_file(targets_path, yaml.dump(target_config, default_flow_style=False))
        targets_paths[JOB_NAMES[ele_type]].append(targets_path)
        as_local_targets_path[JOB_NAMES[ele_type]] = [targets_path]
    _write_prom_conf_file(os.path.join(base, PROM_FILE), as_local_targets_path)
    _write_prom_conf_file(os.path.join(gen_path, PROM_FILE), targets_paths)


def _write_prom_conf_file(config_path, job_dict):
    scrape_configs = []
    for job_name, file_paths in job_dict.items():
        scrape_configs.append({
            'job_name': job_name,
            'file_sd_configs': [{'files': file_paths}],
        })
    config = {
        'global': {
            'scrape_interval': '5s',
            'evaluation_interval': '15s',
            'external_labels': {
                'monitor': 'scion-monitor'
            }
        },
        'scrape_configs': scrape_configs,
    }
    write_file(config_path, yaml.dump(config, default_flow_style=False))

def _prom_addr_of_element(element):
    """Get the prometheus address for a topology element. With element=None, get it for sciond"""
    if not element:
        # this is sciond
        return '127.0.0.1', 32040
    (addrs_selector, public_keyword, bind_keyword, port_keyword) =                                            \
        ('InternalAddrs','PublicOverlay','BindOverlay', 'OverlayPort') if 'InternalAddrs' in element.keys()    \
        else ('Addrs','Public','Bind', 'L4Port')
    addrs = next(iter(element[addrs_selector].values()))
    addr_type = bind_keyword if bind_keyword in addrs.keys() else public_keyword
    port = addrs[addr_type][port_keyword] + PROM_PORT_OFFSET
    return '127.0.0.1', port
