# vent-plugins
This project is a place for Vent plug-ins that will run on the [Vent](https://github.com/CyberReboot/vent) virutal appliance.
Vent is a self-contained virtual appliance based on boot2docker that provides a platform to collect and analyze data across a flexible set of tools and technologies. With vent you can quickly deploy any combination of tools configured in whatever manner makes sense for the environment it is being deployed to and have it all be version controlled by default. See blog post at [IntroducingVent](https://blog.cyberreboot.org/introducing-vent-1d883727b624#.61kl2jgm1)

# templates
Using the templates of vent plug-ins, you can configure how tools will be run. For example, tools can be run adhoc or continuously. With vent, tools can be given slices of the data in isolation or given all of the data being sent to a vent instance. 

# namespaces
Namespaces need templates for their configuration and they need a directory under plug-ins. Within that directory, subsequent directories represent tools that are run under that namespace.

# tools
Tools need to have a dockerfile that runs inside a docker container. Tools can be written in any language and can have any external dependencies as long as it works inside the docker container. The first argument for your tool is automatically assigned a path to the file that the tool is going to process. Additional services are also automatically attached to the tool such as rabbitmq and syslog.

# preconfigured technologies
Out of the box vent comes with a number of preconfigured technologies to make handling the data output of these tools and technologies easier such as logging and indexing for searchability. Plug-ins can leverage these services.

