function remediate_emails(alert_uuids=null, message_ids=null) {

    // query these message_ids or alert_uuids to see what emails are available
    // provide a popup with all of the emails with this message_id (for this company)
    // click to rememdiate

    data = { };
    if (alert_uuids != null)
        data['alert_uuids'] = JSON.stringify(alert_uuids);
    if (message_ids != null)
        data['message_ids'] = JSON.stringify(message_ids);
    
    $.ajax({
        'url': query_message_ids_url, // <-- set in app/templates/base.html
        'data': data,
        'dataType': 'json',
        'error': function(jqXHR, textStatus, errorThrown) {
            alert("ERROR: " + textStatus);
        },
        'method': 'POST',
        'success': function(data, textStatus, jqXHR) {
            var html = '<table class="table table-striped">\
<tr>\
    <td>&nbsp;</td>\
    <td>From</td>\
    <td>To</td>\
    <td>Subject</td>\
</tr>'
            for (var source in data) {
                for (var archive_id in data[source]) {
                    var sender = data[source][archive_id]['sender'];
                    var recipient = data[source][archive_id]['recipient'];
                    var subject = data[source][archive_id]['subject'];
                    var remediated = data[source][archive_id]['remediated'];
                    var remediation_history = data[source][archive_id]['remediation_history'];

                    html += '<tr';
                    if (remediated) {
                        html += ' class="success">';
                    } else {
                        html += '>';
                    }

                        html += '\
    <td><input type="checkbox" ';

                        // if the email has not been remediated then we default to it being selected
                        if (! remediated) 
                            html += ' checked ';

                        html += 'id="cb_archive_id_' + archive_id + '_source_' + source + '"></td>\
    <td>' + sender + '</td>\
    <td>' + recipient + '</td>\
    <td>' + subject + '</td>\
</tr>';
                }
            }

            html += '</table>';

            $('#email-remediation-body').html(html);
            $('#btn-email-remediation').show();
            $('#btn-email-restore').show();
            $('#div-cb-use-phishfry').show();
            $('#btn-email-remediation-done').text("Chicken Out");
            $('#email_remediation_label').text("Email Remediation");

            function execute(action) {
                var request_data = {};
                $('input:checked[id^=cb_archive_id_]').each(function(i, e) {
                    request_data[e.id] = '1';
                });

                request_data['action'] = action;
                request_data['use_phishfry'] = $('#cb-use-phishfry').is(':checked');

                $('#email-remediation-body').html("Sending request...");
                $('#btn-email-remediation').hide();
                $('#btn-email-restore').hide();
                $('#div-cb-use-phishfry').hide();
                $('#btn-email-remediation-done').hide();

                $.ajax({
                    'data': request_data,
                    'dataType': 'json',
                    'error': function(jqXHR, textStatus, errorThrown) {
                        alert("ERROR: " + textStatus);
                    },
                    'method': 'POST',
                    'url': remediate_emails_url, // <-- set in app/templates/base.html
                    'success': function(data, textStatus, jqXHR) {
                        var html = '<table class="table table-striped">\
<tr>\
    <td>Email</td>\
    <td>Result</td>\
    <td>Details</td>\
</tr>';
                        for (var archive_id in data) {
                            var email = data[archive_id]['recipient'];
                            var result_text = data[archive_id]['result_text'];
                            var result_success = data[archive_id]['result_success'];

                            html += '\
<tr>\
    <td>' + email + '</td>\
    <td>' + result_success + '</td>\
    <td>' + result_text + '</td>\
</tr>';

                        }
                        html += '</table>';
                        $('#email_remediation_label').text("Remediation Results");
                        $('#email-remediation-body').html(html);
                        $('#btn-email-remediation').hide();
                        $('#btn-email-restore').hide();
                        $('#div-cb-use-phishfry').hide();
                        $('#btn-email-remediation-done').text("Fantastic");
                        $('#btn-email-remediation-done').show();
                        $('#btn-email-remediation').off('click');
                        $('#btn-email-remediation').click(function(e) {
                            e.preventDefault();
                            $('#email_remediation_modal').modal({
                                show: 'false'
                            });
                        });
                    },
                });
            }

            $('#btn-email-restore').off('click');
            $('#btn-email-restore').click(function(e) {
                e.preventDefault()
                execute(action='restore');
            });

            $('#btn-email-remediation').off('click');
            $('#btn-email-remediation').click(function(e) {
                e.preventDefault();
                execute(action='remove');
            });

            $('#email_remediation_modal').modal({
                show: 'true'
            });
        },
    });
}
