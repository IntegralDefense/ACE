@load ace/ace_local.bro

redef record connection += {
    ace_smtp_state: bool &default=F;
};

function get_target_smtp_filename(c: connection): string {
    return fmt("%s/%s", bro_smtp_dir, c$uid);
}

event connection_established(c: connection) &priority=-5 {
    if (! record_smtp_stream(c))
        return;

    local f:file = open(get_target_smtp_filename(c));
    write_file(f, fmt("%s:%s\n%s\n", c$id$orig_h, c$id$orig_p, strftime("%s", network_time())));
    close(f);

    c$ace_smtp_state = T;
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) {
    if (! record_smtp_stream(c)) 
        return;

    local f:file = open_for_append(get_target_smtp_filename(c));
    write_file(f, fmt("> %s %s\n", command, arg));
    close(f);

    c$ace_smtp_state = T;
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool) {
    if (! record_smtp_stream(c)) 
        return;

    local f:file = open_for_append(get_target_smtp_filename(c));
    write_file(f, fmt("< %s %s %s\n", cmd, code, msg));
    close(f);

    c$ace_smtp_state = T;
}

event smtp_data(c: connection, is_orig: bool, data: string) {
    if (! record_smtp_stream(c)) 
        return;

    local f:file = open_for_append(get_target_smtp_filename(c));
    write_file(f, fmt("%s\n", data));
    close(f);

    c$ace_smtp_state = T;
}

event smtp_starttls(c: connection) {
    if (c$ace_smtp_state) {
        c$ace_smtp_state = F;
        unlink(get_target_smtp_filename(c));
    }
}

event connection_state_remove(c: connection) {
    if (! record_smtp_stream(c)) 
        return;

    # have we started recording this SMTP stream?
    if (! c$ace_smtp_state)
        return;

    local f:file = open(fmt("%s.ready", get_target_smtp_filename(c)));
    close(f);
}
