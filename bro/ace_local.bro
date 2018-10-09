const bro_smtp_dir = "/opt/ace/var/bro/smtp";
const bro_http_dir = "/opt/ace/var/bro/http";

function is_internal(a: addr): bool {
    # returns T if a given address is an internal (owned) address
    return ( a in 10.0.0.0/8
        || a in 192.168.0.0/16
        || a in 172.16.0.0/12 );
}

function record_smtp_stream(c: connection):bool {
    # returns T if this connection is an SMTP session we want
    return c$id$resp_p == 25/tcp || c$id$orig_p == 25/tcp;
}

function record_http_stream(c: connection, data: string):bool {
    # this function receives the first chunk of data from an HTTP stream
    # return T if we should record this chunk of data
    # or F if we should not

    # check the whitelist first...
    if (c$id$orig_h in http_whitelist) return F;
    if (c$id$resp_h in http_whitelist) return F;

    if (/^%[Pp][Dd][Ff]/ in data) return T;
    if (/^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1/ in data) return T;
    if (/^MZ/ in data) return T;
    if (/^\x04\x03\x4b\x50/ in data) return T;

    return F;
}

function log_debug_message(msg: string) {
    local f:file = open_for_append("/opt/ace/logs/bro_debug.log");
    print f, fmt("%s", msg);
    close(f);
}
