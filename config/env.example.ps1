$env:GB_MITM_LOCAL_ORIGIN = "https://localhost:1337"
$env:GB_MITM_LOCAL_HOSTNAMES = "localhost,127.0.0.1"
$env:GB_MITM_LISTEN_HOST = "0.0.0.0"
$env:GB_MITM_LISTEN_PORT = "1337"
$env:GB_MITM_S4_UPSTREAM = "https://s4.example.invalid/"
$env:GB_MITM_IDP_UPSTREAM = "https://ias-cloud.example.invalid/"
$env:GB_MITM_IDP_OD_UPSTREAM = "https://ias-ondemand.example.invalid/"

# Optional. Repeat --certs for each local hostname that needs an explicit certificate.
# The PEM file must contain private key and certificate.
# $env:GB_MITM_CERTS = "--certs localhost=certificates\localhost.pem"
