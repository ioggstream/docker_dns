__author__ = 'rpolli'

inspect_container_pandas_0 = {
    'Id': 'cidpandas0',
    'Same': 'Value',
    'Config': {
        'Hostname': 'furby-pandas',
        'Image': 'impandas'
    },
    'NetworkSettings': {
        'IPAddress': '127.0.0.1'
    },
    'Name': '/cidpandas0',
    'Image': 'imgid_pandas'
}
inspect_container_pandas = {
    'Id': 'cidpandas',
    'Same': 'Value',
    'Config': {
        'Hostname': 'cuddly-pandas',
        'Image': 'impandas'
    },
    'NetworkSettings': {
        'IPAddress': '127.0.0.1'
    },
    'Name': '/cidpandas',
    'Image': 'imgid_pandas'
}
inspect_container_foxes = {
    'Id': 'cidfoxes',
    'Same': 'Value',
    'Config': {
        'Hostname': 'sneaky-foxes',
         'Image': 'imfoxes'
    },
    'NetworkSettings': {
        'IPAddress': '8.8.8.8'
    },
    'Name': '/cidfoxes',
    'Image': 'imgid_foxes'
}
inspect_container_sloths = {
    'Id': 'cidsloths',
    'Config': {
        'Hostname': 'stopped-sloths',
        'Image': 'imsloths'
    },
    'NetworkSettings': {
        'IPAddress': ''
    },
    'Name': '/cidsloths',
    'Image': 'imgid_sloths'
}
inspect_container_returns = {
    'cidpandas0': inspect_container_pandas_0,
    'cidpandas': inspect_container_pandas,
    'cidfoxes': inspect_container_foxes,
    'cidsloths': inspect_container_sloths,
}
containers_return = [
    {'Id': 'cidpandas0'},
    {'Id': 'cidpandas'},
    {'Id': 'cidfoxes'},
    {'Id': 'cidsloths'},
]

mock_list_containers_2 = lambda *a, **k: [
    inspect_container_foxes, inspect_container_pandas, inspect_container_sloths,
    inspect_container_pandas_0
]
mock_inspect_containers_2 = lambda cid, **k: inspect_container_returns[cid]

mock_list_containers = lambda *a, **k: [
    {u'Command': u'/bin/bash',
     u'Created': 1414430175,
     u'Id': u'7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4',
     u'Image': u'eap63_tracer:v6.3.1',
     u'Names': [u'/jboss631'],
     u'Ports': [{u'IP': u'0.0.0.0',
                 u'PrivatePort': 8080,
                 u'PublicPort': 18080,
                 u'Type': u'tcp'},
                {u'IP': u'0.0.0.0',
                 u'PrivatePort': 8787,
                 u'PublicPort': 8787,
                 u'Type': u'tcp'},
                {u'IP': u'0.0.0.0',
                 u'PrivatePort': 9999,
                 u'PublicPort': 19999,
                 u'Type': u'tcp'},
                {u'PrivatePort': 8443, u'Type': u'tcp'},
                {u'PrivatePort': 9990, u'Type': u'tcp'}],
     u'Status': u'Up 2 days'}
]


mock_lookup_container = lambda *a, **k: {
    u'Id': u'7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4',
    u'Image': u'1fc3b15852c8cb8f5b195cee6c3c178b739b77411d9dbebbcbb3d5217f5a6ac6',
    u'Name': u'/jboss631',
    u'Args': [],
    u'Config': {u'AttachStderr': True,
                u'AttachStdin': True,
                u'AttachStdout': True,
                u'Cmd': [u'/bin/bash'],
                u'CpuShares': 0,
                u'Cpuset': u'',
                u'Domainname': u'',
                u'Entrypoint': None,
                u'Env': [u'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'],
                u'ExposedPorts': {u'8080/tcp': {},
                                  u'8443/tcp': {},
                                  u'8787/tcp': {},
                                  u'9990/tcp': {},
                                  u'9999/tcp': {}},
                u'Hostname': u'7d564ceb891b',
                u'Image': u'eap63_tracer:v6.3.1',
                u'Memory': 0,
                u'MemorySwap': 0,
                u'NetworkDisabled': False,
                u'OnBuild': None,
                u'OpenStdin': True,
                u'PortSpecs': None,
                u'StdinOnce': True,
                u'Tty': True,
                u'User': u'',
                u'Volumes': {},
                u'WorkingDir': u''},
    u'Created': u'2014-10-27T17:16:15.261857884Z',
    u'Driver': u'devicemapper',
    u'ExecDriver': u'native-0.2',
    u'HostConfig': {u'Binds': [u'/home/rpolli/Downloads/:/mnt/tmp'],
                    u'CapAdd': None,
                    u'CapDrop': None,
                    u'ContainerIDFile': u'',
                    u'Devices': [],
                    u'Dns': None,
                    u'DnsSearch': None,
                    u'Links': None,
                    u'LxcConf': [],
                    u'NetworkMode': u'bridge',
                    u'PortBindings': {u'8080/tcp': [{u'HostIp': u'', u'HostPort': u'18080'}],
                                      u'8787/tcp': [{u'HostIp': u'', u'HostPort': u'8787'}],
                                      u'9999/tcp': [{u'HostIp': u'', u'HostPort': u'19999'}]},
                    u'Privileged': False,
                    u'PublishAllPorts': False,
                    u'RestartPolicy': {u'MaximumRetryCount': 0, u'Name': u''},
                    u'VolumesFrom': None},
    u'HostnamePath': u'/var/lib/docker/containers/7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4/hostname',
    u'HostsPath': u'/var/lib/docker/containers/7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4/hosts',
    u'MountLabel': u'',
    u'NetworkSettings': {u'Bridge': u'docker0',
                         u'Gateway': u'172.17.42.1',
                         u'IPAddress': u'172.17.0.10',
                         u'IPPrefixLen': 16,
                         u'PortMapping': None,
                         u'Ports': {u'8080/tcp': [{u'HostIp': u'0.0.0.0', u'HostPort': u'18080'}],
                                    u'8443/tcp': None,
                                    u'8787/tcp': [{u'HostIp': u'0.0.0.0', u'HostPort': u'8787'}],
                                    u'9990/tcp': None,
                                    u'9999/tcp': [{u'HostIp': u'0.0.0.0', u'HostPort': u'19999'}]}},
    u'Path': u'/bin/bash',
    u'ProcessLabel': u'',
    u'ResolvConfPath': u'/var/lib/docker/containers/7d564ceb891bb0b2997210936392c1b893e4e438b4fae5b874aa7b5e6137f0d4/resolv.conf',
    u'State': {u'ExitCode': 0,
               u'FinishedAt': u'0001-01-01T00:00:00Z',
               u'Paused': False,
               u'Pid': 8662,
               u'Restarting': False,
               u'Running': True,
               u'StartedAt': u'2014-10-27T17:16:15.756653452Z'},
    u'Volumes': {u'/mnt/tmp': u'/home/rpolli/Downloads'},
    u'VolumesRW': {u'/mnt/tmp': True}
}

SRV_FMT = "_{svc}._{proto}.{container}.docker TTL {cclass} SRV {priority} {weight} {port} {target}"
