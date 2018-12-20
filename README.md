# vent-plugins

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/b2860a6454354fb09e6e835dfe8d6163)](https://www.codacy.com/app/CyberReboot/vent-plugins?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=CyberReboot/vent-plugins&amp;utm_campaign=Badge_Grade)
[![Build Status](https://travis-ci.com/CyberReboot/vent-plugins.svg?branch=master)](https://travis-ci.com/CyberReboot/vent-plugins)
[![codecov](https://codecov.io/gh/CyberReboot/vent-plugins/branch/master/graph/badge.svg)](https://codecov.io/gh/CyberReboot/vent-plugins)
[![Docker Hub Downloads](https://img.shields.io/docker/pulls/cyberreboot/vent-plugins-p0f.svg)](https://hub.docker.com/u/cyberreboot)

This project is a place for plug-ins that run on the [Vent](https://github.com/CyberReboot/vent) virutal appliance.

Vent is a self-contained virtual appliance based on [boot2docker](http://boot2docker.io/) that provides a platform to collect and analyze data across a flexible set of tools and technologies. With Vent you can quickly deploy any combination of tools configured in whatever manner makes sense for the environment it is being deployed to and have it all be version controlled by default. See blog post at [Introducing Vent](https://blog.cyberreboot.org/introducing-vent-1d883727b624#.61kl2jgm1)

# Plugin Layout

*Tools* are collected into *Namespaces*, each of which has a *Template* that defines what files it sees.

## Tools
Tools are the foundational building blocks in Vent. Each tool knows how to process a particular family of file types and turn them into a useful output.

Tools run inside a Docker container, so they need to have a dockerfile. They can be written in any language and can have any external dependencies as long as it works inside the docker container. Each tool has it's own folder, e.g. `vent-plugins/plugins/network/tcpdump_hex_parser`

Vent provides a number of services for your tool:
 - When your tool is invoked, the first argument is the path to the file that the tool should process.
 - Additional services like rabbitmq and syslog are automatically attached to the container.
 - File management and user output are managed for you, so the tool can be stateless.

## Namespaces
Namespaces are simply folders that group Tools that handle similar inputs. e.g. `vent-plugins/plugins/network/`

## Templates
Templates define when the Tools within a particular Namespace will be invoked. Specifically, they define:

 - Which files a namespace can process (by extenions and MIME Type)
 - How often to invoke the namespace against matching files (e.g. continuously, hourly, adhoc)
 - Tools can be given slices of the data in isolation or given all of the data being sent to a vent instance. 

# preconfigured technologies
Out of the box vent comes with a number of preconfigured technologies to make handling the data output of these tools and technologies easier such as logging and indexing for searchability. Plug-ins can leverage these services.

