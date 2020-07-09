#!/bin/bash

WhoisIP(){
        echo -e "[AS$found_asn] $found_asname"
}

LookupASNAndRouteFromIP(){
        found_route=""
        found_asn=""
        found_asname=""
        output=$(whois -h whois.cymru.com " -f -p $1" | sed -e 's/\ *|\ */|/g')
        found_asn=$(echo $output | awk -F'[|]' {'print $1'})
        found_asname=$(echo $output | awk -F'[|]' {'print $4'})
        found_route=$(echo $output | awk -F'[|]' {'print $3'})
}

ResolveHostnameToIPList(){
        ip=$(host $1 | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
        echo -e "$ip\n"
}

input=$(echo $1 | sed -e 's/\/.*//g' | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
if [ -z "$input" ]; then
        # Input is not an IPv4 Address. Check if it is a number (ASN)
        asn=$(echo $1 | sed -e 's/[a|A][s|S]//g' | grep -E "^[0-9]*$")
        if [ -z "$asn" ]; then
                # Input is not an ASN either. Consider it a hostname and try to resolve it.
                ip=$(ResolveHostnameToIPList $1)
                if [ -z "$ip" ]; then
                        echo -e "[ASNA] NA"
                        exit
                fi
                numips=$(echo "$ip" | wc -l)
                [[ $numips = 1 ]] && s="" || s="es"
                for singleip in $ip; do
                        LookupASNAndRouteFromIP $singleip
                        WhoisIP $singleip
                done
                exit
        else
                echo -e "[ASNA] NA"
                exit
        fi
else
        # Input is an IPv4
        LookupASNAndRouteFromIP $input
        if [ -z "$found_asname" ] && [ -z "$found_route" ]; then
                echo -e "[ASNA] NA"
                exit
        fi
        WhoisIP $input
        exit
fi
