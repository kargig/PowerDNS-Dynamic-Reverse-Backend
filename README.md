# PowerDNS Dynamic Reverse Backend

Original dynamic reverse pipe backend for PowerDNS: **pdns-dynamic-reverse-backend.py**

Modified version to support IPv6: **pipe-local-ipv6-wrapper.py**

## How to use
### pdns.conf
```
launch=pipe
pipe-command=/usr/local/sbin/pipe-local-ipv6-wrapper
pipe-timeout=500
```
### pipe backend configuration
Sample configuration files for the pipe backend exist in 'sample-configs' directory. They should be placed in **/etc/powerdns/configs/**

**defaults.config** contains generic SOA record information
**prefixes.config** contains zone information. Zones inherit SOA data from defaults.config settings.

## Example usage
Using the following config (round delegation)
```
[2001:db8:2002::/48]
defaults = DYNDSL6
options = {'prefix': 'dsl-p', 'postfix': '', 'forward': 'dyn6.example.com', 'version': 6,  'showclientid': 1, 'nrdelegation': 0}
```
The output is:
```
$ dig +short -x 2001:db8:2002::1 @ns-power1.example.com
dsl-p0-1.dyn6.example.com.
$ dig +short -x 2001:db8:2002:1::1 @ns-power1.example.com
dsl-p1-1.dyn6.example.com.
$ dig +short -x 2001:db8:2002:ffaa:aaaa:bbbb::1 @ns-power1.example.com
dsl-p65450-2lfljc4irk001.dyn6.example.com.
```

Using the following config (non-round delegation)
```
[2001:db8:3000::/40]
defaults = DYNDSL6
options = {'prefix': 'dsl-h', 'postfix': '', 'forward': 'dyn6.example.com', 'version': 6,  'showclientid': 1, 'nrdelegation': 1}
```
The output is:
```
$ dig +short -x 2001:db8:3000:0000::1 @ns-power1.example.com
dsl-h0-1.dyn6.example.com.
$ dig +short -x 2001:db8:3000:0100::1 @ns-power1.example.com
dsl-h1-rkq6daidfxmxhd.dyn6.example.com.
$ dig +short -x 2001:db8:3000:0200::1 @ns-power1.example.com
dsl-h2-1j5gcql0qvv9uyp.dyn6.example.com.
```

## LICENSE

The MIT License

Copyright (c) 2009 Wijnand "maze" Modderman
Copyright (c) 2010 Stefan "ZaphodB" Schmidt
Copyright (c) 2011 Endre Szabo
Copyright (c) 2012-2015 George Kargiotakis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
