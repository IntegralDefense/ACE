@load ace/ace_local.bro

function get_target_filename(c: connection): string {
    return fmt("%s/%s", bro_smtp_dir, c$uid);
}

event connection_established(c: connection) &priority=-5 {
    if (! record_smtp_stream(c))
        return;

    local f:file = open(get_target_filename(c));
    write_file(f, fmt("%s:%s\n%s\n", c$id$orig_h, c$id$orig_p, strftime("%s", network_time())));
    close(f);
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) {
    if (! record_smtp_stream(c)) 
        return;

    local f:file = open_for_append(get_target_filename(c));
    write_file(f, fmt("> %s %s\n", command, arg));
    close(f);
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool) {
    if (! record_smtp_stream(c)) 
        return;

    local f:file = open_for_append(get_target_filename(c));
    write_file(f, fmt("< %s %s %s\n", cmd, code, msg));
    close(f);
}

event smtp_data(c: connection, is_orig: bool, data: string) {
    if (! record_smtp_stream(c)) 
        return;

    local f:file = open_for_append(get_target_filename(c));
    write_file(f, fmt("%s\n", data));
    close(f);
}

event connection_state_remove(c: connection) {
    if (! record_smtp_stream(c)) 
        return;

    local f:file = open(fmt("%s.ready", get_target_filename(c)));
    close(f);
}
