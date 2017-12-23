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
from collections import defaultdict
from string import Template

# SCION
from lib.crypto.asymcrypto import (
    get_enc_key_file_path,
    get_sig_key_file_path,
)
from lib.crypto.certificate_chain import get_cert_chain_file_path
from lib.crypto.trc import get_trc_file_path
from lib.defines import (
    AS_CONF_FILE,
    GEN_PATH,
    PROJECT_ROOT,
    PROM_FILE,
)
from lib.util import (
    copy_file,
    read_file,
    write_file,
)
from topology.generator import (
    _topo_json_to_yaml,
    DEFAULT_PATH_POLICY_FILE,
    INITIAL_CERT_VERSION,
    INITIAL_TRC_VERSION,
    PATH_POLICY_FILE,
)

TYPES_TO_EXECUTABLES = {
    'router': 'border',
    'beacon_server': 'beacon_server',
    'path_server': 'path_server',
    'certificate_server': 'cert_server',
    'sibra_server': 'sibra_server'
}

TYPES_TO_KEYS = {
    'beacon_server': 'BeaconService',
    'certificate_server': 'CertificateService',
    'router': 'BorderRouters',
    'path_server': 'PathService',
    'sibra_server': 'SibraService'
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


class ASCredential(object):
    """
    A class to keep the credentials of the SCION ASes.
    """
    def __init__(self, sig_priv_key, enc_priv_key, certificate, trc, master_as_key):
        self.sig_priv_key = sig_priv_key
        self.enc_priv_key = enc_priv_key
        self.certificate = certificate
        self.trc = trc
        self.master_as_key = master_as_key


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
    config = configparser.ConfigParser()
    env_tmpl = 'PYTHONPATH=python:.,ZLOG_CFG="%s/%s.zlog.conf"'
    if not instance_dict:
        cmd = ('bash -c \'exec %s "--api-addr" "%s" "%s" "%s" &>logs/%s.OUT\'') % (
            executable_name, "/run/shm/sciond/%s.sock" % instance_name, instance_name,
            get_elem_dir(GEN_PATH, isd_as, "endhost"), instance_name)
        env = 'PYTHONPATH=python:.'
    elif service_type == 'router':  # go router
        env_tmpl += ',GODEBUG="cgocheck=0"'
        prom_addr = "%s:%s" % (instance_dict['InternalAddrs'][0]['Public'][0]['Addr'],
                               instance_dict['InternalAddrs'][0]['Public'][0]['L4Port'] +
                               PROM_PORT_OFFSET)
        cmd = ('bash -c \'exec bin/%s -id "%s" -confd "%s" -prom "%s" &>logs/%s.OUT\'') % (
            executable_name, instance_name, get_elem_dir(GEN_PATH, isd_as, instance_name),
            prom_addr, instance_name)
        env = env_tmpl % (get_elem_dir(GEN_PATH, isd_as, instance_name),
                          instance_name)
    else:  # other infrastructure elements
        prom_addr = "%s:%s" % (instance_dict['Public'][0]['Addr'],
                               instance_dict['Public'][0]['L4Port'] + PROM_PORT_OFFSET)
        cmd = ('bash -c \'exec bin/%s "%s" "%s" --prom "%s" &>logs/%s.OUT\'') % (
            executable_name, instance_name, get_elem_dir(GEN_PATH, isd_as, instance_name),
            prom_addr, instance_name)
        env = env_tmpl % (get_elem_dir(GEN_PATH, isd_as, instance_name),
                          instance_name)
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


def generate_zk_config(tp, isd_as, local_gen_path, simple_conf_mode):
    """
    Generates Zookeeper configuration files for Zookeeper instances of an AS.
    :param dict tp: the topology of the AS provided as a dict of dicts.
    :param ISD_AS isd_as: ISD-AS for which the ZK config will be written.
    :param str local_gen_path: The gen path of scion-web.
    """
    for zk_id, zk in tp['ZookeeperService'].items():
        instance_name = 'zk%s-%s-%s' % (isd_as[0], isd_as[1], zk_id)
        write_zk_conf(local_gen_path, isd_as, instance_name, zk, simple_conf_mode)


def write_zk_conf(local_gen_path, isd_as, instance_name, zk, simple_conf_mode):
    """
    Writes a Zookeeper configuration file for the given Zookeeper instance.
    :param str local_gen_path: The gen path of scion-web.
    :param ISD_AS isd_as: ISD-AS for which the ZK config will be written.
    :param str instance_name: the instance of the ZK service (e.g. zk1-5-1).
    :param dict zk: Zookeeper instance information from the topology as a
    dictionary.
    """
    conf = {
        'tickTime': 100,
        'initLimit': 10,
        'syncLimit': 5,
        'dataDir': '/var/lib/zookeeper',
        'clientPort': zk['L4Port'],
        'maxClientCnxns': 0,
        'autopurge.purgeInterval': 1,
    }
    if simple_conf_mode:
        conf['clientPortAddress'] = '127.0.0.1'
    else:
        # set the dataLogDir only if we are operating in the normal mode.
        conf['dataLogDir'] = '/run/shm/host-zk'
    zk_conf_path = get_elem_dir(local_gen_path, isd_as, instance_name)
    zk_conf_file = os.path.join(zk_conf_path, 'zoo.cfg')
    write_file(zk_conf_file, yaml.dump(conf, default_flow_style=False))


def get_elem_dir(path, isd_as, elem_id):
    """
    Generates and returns the directory of a SCION element.
    :param str path: Relative or absolute path.
    :param ISD_AS isd_as: ISD-AS to which the element belongs.
    :param elem_id: The name of the instance.
    :returns: The directory of the instance.
    :rtype: string
    """
    return "%s/ISD%s/AS%s/%s" % (path, isd_as[0], isd_as[1], elem_id)


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
    topo_yml = _topo_json_to_yaml(tp)
    path = os.path.join(instance_path, 'topology.yml')
    with open(path, 'w') as file:
        yaml.dump(topo_yml, file, default_flow_style=False)


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
    :param str instance_path: Location (in the file system) to write
    the configuration into.
    """
    # write keys
    sig_path = get_sig_key_file_path(instance_path)
    enc_path = get_enc_key_file_path(instance_path)
    write_file(sig_path, as_obj.sig_priv_key)
    write_file(enc_path, as_obj.enc_priv_key)
    # write cert
    cert_chain_path = get_cert_chain_file_path(
        instance_path, isd_as, INITIAL_CERT_VERSION)
    write_file(cert_chain_path, as_obj.certificate)
    # write trc
    trc_path = get_trc_file_path(instance_path, isd_as[0], INITIAL_TRC_VERSION)
    write_file(trc_path, as_obj.trc)


def write_as_conf_and_path_policy(isd_as, as_obj, instance_path):
    """
    Writes AS configuration (i.e. as.yml) and path policy files.
    :param ISD_AS isd_as: ISD-AS for which the config will be written.
    :param str instance_path: Location (in the file system) to write
    the configuration into.
    """
    conf = {
        'MasterASKey': as_obj.master_as_key,
        'RegisterTime': 5,
        'PropagateTime': 5,
        'CertChainVersion': 0,
        'RegisterPath': True,
    }
    conf_file = os.path.join(instance_path, AS_CONF_FILE)
    write_file(conf_file, yaml.dump(conf, default_flow_style=False))
    path_policy_file = os.path.join(PROJECT_ROOT, DEFAULT_PATH_POLICY_FILE)
    copy_file(path_policy_file, os.path.join(instance_path, PATH_POLICY_FILE))


def generate_sciond_config(isd_as, as_obj, topo_dicts):
    executable_name = "bin/sciond"
    instance_name = "sd%s" % str(isd_as)
    service_type = "endhost"
    instance_path = get_elem_dir(GEN_PATH, isd_as, service_type)
    processes = []
    for svc_type in ["BorderRouters", "BeaconService", "CertificateService",
                     "HiddenPathService", "PathService"]:
        if svc_type not in topo_dicts:
            continue
        for elem_id, elem in topo_dicts[svc_type].items():
            processes.append(elem_id)
    processes.append(instance_name)
    config = prep_supervisord_conf(None, executable_name, service_type, instance_name, isd_as)
    config['group:' + "as%s" % str(isd_as)] = {'programs': ",".join(processes)}
    write_certs_trc_keys(isd_as, as_obj, instance_path)
    write_as_conf_and_path_policy(isd_as, as_obj, instance_path)
    write_supervisord_config(config, os.path.join(GEN_PATH, isd_as.ISD(), isd_as.AS()))
    write_topology_file(topo_dicts, None, instance_path)


def generate_prom_config(isd_as, topo_dicts):
    """
    """
    config_dict = defaultdict(list)
    for br_id, br_ele in topo_dicts['BorderRouters'].items():
        config_dict['BorderRouters'].append(_prom_addr_br(br_ele))
    for svc_type in ["BeaconService", "CertificateService",
                     "HiddenPathService", "PathService"]:
        if svc_type not in topo_dicts:
            continue
        for elem_id, elem in topo_dicts[svc_type].items():
            config_dict[svc_type].append(_prom_addr_infra(elem))
    _write_prom_files(isd_as, config_dict)


def _write_prom_files(isd_as, config_dict):
    base = os.path.join(GEN_PATH, isd_as.ISD(), isd_as.AS())
    as_local_targets_path = {}
    targets_paths = defaultdict(list)
    for ele_type, target_list in config_dict.items():
        targets_path = os.path.join(base, PROM_DIR, TARGET_FILES[ele_type])
        target_config = [{'targets': target_list}]
        write_file(targets_path, yaml.dump(target_config, default_flow_style=False))
        targets_paths[JOB_NAMES[ele_type]].append(targets_path)
        as_local_targets_path[JOB_NAMES[ele_type]] = [targets_path]
    _write_prom_conf_file(os.path.join(base, PROM_FILE), as_local_targets_path)
    _write_prom_conf_file(os.path.join(GEN_PATH, PROM_FILE), targets_paths)


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


def _prom_addr_br(br_ele):
    """Get the prometheus address for a border router"""
    int_addr = br_ele['InternalAddrs'][0]['Public'][0]
    return "[%s]:%s" % (int_addr['Addr'], int_addr['L4Port'] + PROM_PORT_OFFSET)


def _prom_addr_infra(infra_ele):
    """Get the prometheus address for an infrastructure element."""
    int_addr = infra_ele["Public"][0]
    return "[%s]:%s" % (int_addr["Addr"], int_addr["L4Port"] + PROM_PORT_OFFSET)
