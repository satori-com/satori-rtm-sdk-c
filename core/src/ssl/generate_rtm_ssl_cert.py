#!/usr/bin/env python3
# encoding: utf-8

import base64
import itertools
import os
import re
import subprocess

# Extract all certificates from the certificate chain used to verify x.api.satori.com
certificate_chain_text = subprocess.check_output("openssl s_client -showcerts -verify 999 -connect x.api.satori.com:443 </dev/null", shell=True, stderr=subprocess.STDOUT)

# We are interested at the last (closest to the root) one
certificate_chain = re.findall(b"(?s)(-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----)", certificate_chain_text)
last_certificate = certificate_chain[-1]

# Decode the certificate and reencode as a C uint8_t array
certificate_data_raw = base64.b64decode(b"".join(last_certificate.split(b"\n")[1:-1]))

certificate_data = []
for _, line in itertools.groupby(enumerate(certificate_data_raw), lambda x: int(x[0] / 40)):
  for _, entry in line:
    certificate_data.append(b"0x%02x, " % entry)
  certificate_data[-1] = certificate_data[-1][:-1] + b"\n  "
certificate_data[-1] = certificate_data[-1][:certificate_data[-1].find(b",")]

# Also create a text version for the source file
text_formatter = subprocess.Popen("openssl x509 -text -noout", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
cert_as_text, _ = text_formatter.communicate(last_certificate)

# Create a new rtm_ssl_cert.c file
output = b"""
/* Root certificate for current satori endpoints
 *
 * %s
 *
 * See generate_rtm_ssl_cert.py for how to regenerate upon an update.
 */

#include <stdint.h>
#include <stdlib.h>

const uint8_t _rtm_ssl_cert[] = {
  %s
};

const size_t _rtm_ssl_cert_size = sizeof(_rtm_ssl_cert);
""" % (cert_as_text.replace(b"\n", b"\n * "), b"".join(certificate_data))

with open("rtm_ssl_cert.c.new", "wb") as outfile:
  outfile.write(output)

if os.path.isfile("rtm_ssl_cert.c"):
  os.unlink("rtm_ssl_cert.c")
os.rename("rtm_ssl_cert.c.new", "rtm_ssl_cert.c")
