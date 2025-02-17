#!/usr/bin/env python

# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import print_function
from six import string_types

import collections

try:
    collectionsAbc = collections.abc
except AttributeError:
    collectionsAbc = collections

from glanceclient import client as glance_client
from heatclient import client as heat_client
from ironicclient import client as ironic_client
from keystoneauth1.identity import generic as ks_id
from keystoneauth1 import session as ks_session
from novaclient import client as nova_client
from swiftclient.client import Connection


def get_auth_session(auth_variables):
    auth_url = auth_variables.get('auth_url')
    username = auth_variables.get('username')
    project_name = auth_variables.get('project_name')
    auth_token = auth_variables.get('os_auth_token')
    password = auth_variables.get('password')
    cacert = auth_variables.get('cacert')
    timeout = auth_variables.get('timeout')

    if auth_token:
        auth = ks_id.Token(auth_url=auth_url,
                           token=auth_token,
                           project_name=project_name,
                           project_domain_id='default')
    else:
        auth = ks_id.Password(auth_url=auth_url,
                              username=username,
                              password=password,
                              project_name=project_name,
                              user_domain_id='default',
                              project_domain_id='default')
    return ks_session.Session(auth=auth, verify=cacert, timeout=timeout)


def get_swift_client(auth_variables):
    return Connection(preauthurl=auth_variables.get('undercloud_swift_url'),
                      preauthtoken=auth_variables.get('os_auth_token'),
                      retries=10,
                      starting_backoff=3,
                      max_backoff=120)


def get_nova_client(auth_variables):
    return nova_client.Client(2, session=get_auth_session(auth_variables))


def get_glance_client(auth_variables):
    return glance_client.Client(2, session=get_auth_session(auth_variables))


def get_heat_client(auth_variables):
    return heat_client.Client('1', session=get_auth_session(auth_variables))


def get_ironic_client(auth_variables):
    session = get_auth_session(auth_variables)
    ironic_url = session.get_endpoint(service_type='baremetal',
                                      interface='public')
    return ironic_client.get_client(
        1,
        ironic_url=ironic_url,
        os_auth_token=auth_variables.get('os_auth_token')
    )


def filtered(obj):
    """Only return properties of obj whose value can be properly serialized."""
    return {k: v for k, v in obj.__dict__.items()
            if isinstance(v, (string_types, int, list, dict, type(None)))}


def get_nested(data, name, path):
    # Finds and returns a property from a nested dictionary by
    # following a path of a defined set of property names and types.

    def deep_find_key(key_data, data, name):
        key, instance_type, instance_name = key_data
        if key in data:
            if not isinstance(data[key], instance_type):
                raise ValueError("The '{}' property of '{}' must be a {}."
                                 "".format(key, name, instance_name))
            return data[key]
        for k, v in sorted(data.items()):
            if isinstance(v, collectionsAbc.Mapping):
                return deep_find_key(key_data, v, name)
        return None

    if not isinstance(data, collectionsAbc.Mapping):
        raise ValueError(
            "'{}' is not a valid resource.".format(name))

    current_value = data
    while len(path) > 0:
        key_data = path.pop(0)
        current_value = deep_find_key(key_data, current_value, name)
        if current_value is None:
            break

    return current_value
