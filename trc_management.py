#!/usr/bin/python3
# Copyright 2018 ETH Zurich
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

import argparse
import os
import sys
import base64
import time
import copy

from topology.generator import (
    TopoID, 
    DEFAULT_KEYGEN_ALG, 
    MAX_QUORUM_TRC,
)

from lib.crypto.trc import (
    OFFLINE_KEY_ALG_STRING,
    OFFLINE_KEY_STRING,
    ONLINE_KEY_ALG_STRING,
    ONLINE_KEY_STRING,
    TRC,
)

from lib.crypto.util import get_online_key_file_path
from nacl.signing import SigningKey, VerifyKey


ONLINE_PRIVATE_KEY_STRING = 'PrivateOnlineKey'
DEFAULT_TRC_VALIDITY = 365 * 24 * 60 * 60

def find_trc(trc_file):
    try:
        with open(trc_file) as f:
            data = f.read()
    except Exception as ex:
        print(ex)
        sys.exit(1)
    trc = TRC.from_raw(data)
    return trc

def read_key_from_file(key_file):
    try:
        with open(key_file) as f:
            data = f.read()
        return base64.b64decode(data)
    except Exception as ex:
        print(ex)
        sys.exit(1)

def get_signing_keys_from_paths(service_paths):
    """
    :param dict service_paths: is a dictionary like: service_paths[1-11] = './gen/ISD1/AS11/cs1-11-1'
    """
    key_map = {}
    for name, path in service_paths.items():
        pathDict = {}
        pathDict[ONLINE_KEY_ALG_STRING] = DEFAULT_KEYGEN_ALG
        priv = read_key_from_file(os.path.join(path, 'keys', 'online-root.seed'))
        s = SigningKey(priv)
        # this private key will not appear in the TRC, but we need it to sign it:
        pathDict[ONLINE_PRIVATE_KEY_STRING] = priv
        # we derive the public key from the private one
        pathDict[ONLINE_KEY_STRING] = s.verify_key.encode()
        # same for offline:
        pathDict[OFFLINE_KEY_ALG_STRING] = DEFAULT_KEYGEN_ALG
        priv = read_key_from_file(os.path.join(path, 'keys', 'offline-root.seed'))
        s = SigningKey(priv)
        pathDict[OFFLINE_KEY_STRING] = s.verify_key.encode()
        key_map[name] = pathDict
    return key_map

def get_signing_keys_fromISD_directory(core_ases, location_of_ISD):
    paths = {}
    for name in core_ases:
        ia = TopoID(name)
        path = os.path.join(location_of_ISD, ia.AS(), 'cs' + name + '-1')
        paths[name] = path
    return get_signing_keys_from_paths(paths)

def reissue_trc(trc, key_map):
    """
    Generates a new TRC based on the previous one, and the contents of the key_map
    :return the new generated TRC
    :param dict key_map: with ISD-AS as key, and values are dictionaries as well.
    Each one contains 5 keys:
        ONLINE_PRIVATE_KEY_STRING   : the online private key of ISD-AS; used to sign the TRC, the key won't appear in the TRC
        ONLINE_KEY_ALG_STRING       : always ed25519
        ONLINE_KEY_STRING           : the online public key of ISD-AS, included in the TRC
        OFFLINE_KEY_ALG_STRING      : same as online
        OFFLINE_KEY_STRING          : same as online
    """
    trc = copy.deepcopy(trc)
    trc.signatures = {}

    # list core ASes:
    trc.core_ases = {name: {key:keys[key] for key in [ONLINE_KEY_ALG_STRING, ONLINE_KEY_STRING, OFFLINE_KEY_ALG_STRING, OFFLINE_KEY_STRING]} for name, keys in key_map.items()}
    # update version:
    trc.version += 1
    # quorum:
    trc.quorum_trc = min(len(key_map), MAX_QUORUM_TRC)
    # expiration time:
    now = int(time.time())
    trc.create_time = now
    trc.exp_time = now + DEFAULT_TRC_VALIDITY

    # sign with core ASes keys:
    for name, keys in key_map.items():
        trc.sign(name, keys[ONLINE_PRIVATE_KEY_STRING])
    return trc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--trc-file', required=True, help='Location of the TRC file in the old gen folder')
    parser.add_argument('-c', '--core-ases', nargs='+', help='List of names of the Core ASes that will appear in the TRC')
    parser.add_argument('-a', '--append', help='AS folder of the new to be appended AS. E.g. ./gen/ISD1/AS1010')
    args = parser.parse_args()
    if (args.append is None and args.core_ases is None) or (args.append is not None and args.core_ases is not None):
        print("Need to specify ONE OF --core-ases OR --append")
        sys.exit(1)
    
    trc = find_trc(args.trc_file)
    ases_to_reissue = args.core_ases if args.core_ases is not None else trc.core_ases
    key_map = get_signing_keys_fromISD_directory(ases_to_reissue, os.path.join(os.path.dirname(args.trc_file), '..', '..', '..'))
    if args.append is not None:
        ASID = os.path.basename(os.path.normpath(args.append))
        ASID = ASID[2:]
        ISDID = os.path.basename(os.path.normpath(os.path.join(args.append, '..')))
        ISDID = ISDID[3:]
        IA = "%s-%s" % (ISDID, ASID)
        service_path = os.path.join(args.append, "cs%s-1" % IA)
        extra_keys = get_signing_keys_from_paths({IA: service_path})
        key_map = {**key_map, **extra_keys}

    trc = reissue_trc(trc, key_map)
    print(trc)

if __name__ == "__main__":
    main()
