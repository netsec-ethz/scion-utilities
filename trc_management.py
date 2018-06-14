#!/usr/bin/python3
# Copyright 2014 ETH Zurich
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

# from lib.packet.scion_addr import ISD_AS
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

# DEFAULT_KEYGEN_ALG = 'ed25519'
ONLINE_PRIVATE_KEY_STRING = 'PrivateOnlineKey'


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
    service_paths is a dictionary like:
    service_paths[ISD-AS] = './gen/ISD1/AS11/cs1-11-1'
    """
    key_map = {}
    for name, path in service_paths.items():
        key_map[name] = {}
        key_map[name][ONLINE_KEY_ALG_STRING] = DEFAULT_KEYGEN_ALG
        priv = read_key_from_file(os.path.join(path, 'keys', 'online-root.seed'))
        s = SigningKey(priv)
        # this private key will not appear in the TRC, but we need it to sign it:
        key_map[name][ONLINE_PRIVATE_KEY_STRING] = priv
        # we derive the public key from the private one
        key_map[name][ONLINE_KEY_STRING] = s.verify_key.encode()
        # same for offline:
        key_map[name][OFFLINE_KEY_ALG_STRING] = DEFAULT_KEYGEN_ALG
        priv = read_key_from_file(os.path.join(path, 'keys', 'offline-root.seed'))
        s = SigningKey(priv)
        key_map[name][OFFLINE_KEY_STRING] = s.verify_key.encode()
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
    The key_map[ISD-AS] contains 5 keys:
        ONLINE_PRIVATE_KEY_STRING   : the online private key of ISD-AS; used to sign the TRC, the key won't appear in the TRC
        ONLINE_KEY_ALG_STRING       : always ed25519
        ONLINE_KEY_STRING           : the online public key of ISD-AS, included in the TRC
        OFFLINE_KEY_ALG_STRING      : same as online
        OFFLINE_KEY_STRING          : same as online
    """
    trc.signatures = {}
    trc.core_ases = {}
    # list core ASes:
    for name, keys in key_map.items():
        trc.core_ases[name] = {}
        trc.core_ases[name][ONLINE_KEY_ALG_STRING] = keys[ONLINE_KEY_ALG_STRING]
        trc.core_ases[name][ONLINE_KEY_STRING] = keys[ONLINE_KEY_STRING]
        trc.core_ases[name][OFFLINE_KEY_ALG_STRING] = keys[OFFLINE_KEY_ALG_STRING]
        trc.core_ases[name][OFFLINE_KEY_STRING] = keys[OFFLINE_KEY_STRING]
    # update version:
    trc.version += 1
    # quorum:
    trc.quorum_trc = min(len(key_map), MAX_QUORUM_TRC)
    # expiration time:
    now = int(time.time())
    trc.create_time = now
    trc.exp_time = now + TRC.VALIDITY_PERIOD
    # sign with core ASes keys:
    for name, keys in key_map.items():
        trc.sign(name, keys[ONLINE_PRIVATE_KEY_STRING])
    return trc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--trc-file', required=True, help='Location of the TRC file in the old gen folder')
    parser.add_argument('-c', '--core-ases', nargs='+', help='List of names of the Core ASes that will appear in the TRC')
    parser.add_argument('-a', '--append', help='AS folder of the new to be appended AS. E.g. ./gen/ISD1/AS1010')
    # parser.add_argument('-n', '--dry-run', action='store_true')
    args = parser.parse_args()
    if (args.append is None and args.core_ases is None) or (args.append is not None and args.core_ases is not None):
        print("Need to specify --core-ases OR --append")
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
