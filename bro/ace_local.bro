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

function log_debug_message(msg: string) {
    local f:file = open_for_append("/opt/ace/extra_bro/debug_bro.txt");
    print f, fmt("%s", msg);
    close(f);
}
