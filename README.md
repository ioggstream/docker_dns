Docker DNS
==========

A simple Twisted DNS server using custom TLD and Docker Event interface as the back end for IP
resolution. As a plus you get a sperimental SFTP server to access Docker Volumes.

Containers can be found by: 
 - image name
 - container name
 - hostname
 - ip

eg: here are some examples

    #host busybox.*.docker        # search all busybox containers
    #host 26ed50b1bf59.docker     # search a container by hostname (not by ID!)
    #host nice_bohr.docker        # search a container by name

You can lookup different records:
 - 'A' record: query a container NAME or HOSTNAME that will match a container with a docker inspect
   command with '.docker' as the TLD. eg: mysql_server1.docker
 - 'SRV' record query exposing the NAT informations (more to come!)
 - 'PTR' record, with reverse pointer

Note: This fork of docker_dns  *always* requires to query using a TLD (by default .docker)

Install/Run
-----------

Just install from requirements (in a virtualenv if you'd like)

    #pip install -r requirements.txt 

That's it! To run, remember that you may need to set user/group ids on 
the process


    #sudo twistd -gdocker -y dockerdns  -p 53

This will start a DNS server on port 53 (default DNS port). To make this
useful, you probably want to combine it with your regular DNS in something like Dnsmasq.

You can get configuration parameters with
    
    #sudo twistd dockerdns --help


There's a simple HTTP console to check the internal mappings. You can curl it with

    #curl -v http://localhost:8080/{hostname,image,name,id,ping,help,ip}/{optional_key}

DNS Examples
--------
Dig output is shortened for brevity. We have Docker containers like this:

    ID                  IMAGE             STATUS              Names
    26ed50b1bf59        ubuntu:12.04      Up 1 hour           sad_turing
    0949efde23bf        ubuntu:12.04      Up 18 hours         happy_bohr

0949efde23bf has:

 - ID: 0949efde23bf01727203638dafb0ac15b2e68db9effe03b90687d67a96ab6ee7
 - IP: 172.17.0.2
 - Hostname: 0949efde23bf

26ed50b1bf59 has:

 - ID: 26ed50b1bf5947727bee4910f3d93674d823496c615940238219b5346cc0fc4e
 - IP: 172.17.0.3
 - Hostname: my-thing

Search by Hostname (uses default or explicit hostname)

    #dig +short 26ed50b1bf59.docker
    172.17.0.2

    #dig +short my-thing.docker
    172.17.0.3

Search by Names (works only the first Name)

    #dig +short sad_turing.docker
    172.17.0.2

    #dig +short happy_bohr.docker
    172.17.0.3


When a container doesn't exist, no answer is given:

    dig nothing.docker
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 24269
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

You can search by image, like skydock:

    dig +short ubuntu.*.docker
    172.17.0.2
    172.17.0.3

Nat discovery: you can discover natted ports with queries like this one

    dig _8080._tcp.my-thing.docker srv
    ;; ANSWER SECTION:
    _8080._tcp.jboss631.docker. 10  IN      SRV     100 100 18080 192.168.204.17.


SFTP Examples
-------------
To access the /myshare volume on the container jboss631, just:

    #sftp -P10022 jboss631@localhost # empty password
    #ls /
    /myshare
    


Configuration
-------------
Config is done in the `dockerdns.json` file. There's a skeleton in
`dockerdns.json.sample`. Below are the default config values. Currently,
configuration is rather limited.

    {
        "#": "# URL to connect to the Docker API. docker-py defaults to unix://var/run/docker.sock",
        'docker_url': None

        "#": "# socket.bind defaults to 0.0.0.0",
        'bind_interface': '',
        'bind_port': 53,
        'bind_protocols': ['tcp', 'udp'],

        "#": "Return SERVFAIL instead of NXDOMAIN if no matching container found"
        'no_nxdomain': True,

        "#": "Makes successful requests authoritative",
        'authoritative': True,
    }

Contributing
------------
There are plenty of FIXME comments dotted around the code. No list of feature
ideas yet, but there is scope for big improvements to current simple
functionality.

All pull requests should 10/10 in pylint, have no PEP8 warnings and should
include reasonable test coverage.

To run:

 - `pip install -r test_requirements.txt --use-mirrors`
 - `pylint --rcfile=pylint.conf *.py`
 - `pep8 *.py`
