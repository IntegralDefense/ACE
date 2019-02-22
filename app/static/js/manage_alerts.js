// alert management

function get_all_checked_alerts() {
    // returns the list of all checked alert IDs
    var result = Array();
    $("input[name^='detail_']").each(function(index) {
        var $this = $(this);
        if ($this.is(":checked")){
            result.push($this.prop("name").replace(/^detail_/, ""));
        } 
    });

    return result;
}

$(document).ready(function() {
    $("#master_checkbox").change(function(e) {
        $("input[name^='detail_']").prop('checked', $("#master_checkbox").prop('checked'));
    });

    $("#btn-disposition").click(function(e) {
        // compile a list of all the alerts that are checked
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            // XXX do this on the disposition button
            alert("You must select one or more alerts to disposition.");
            return;
        }

        // add a hidden field to the form
        $("#disposition-form").append('<input type="hidden" name="alert_uuids" value="' + all_alert_uuids.join(",") + '" />');

        // and then allow the form to follow through
    });

    $("#btn-add-to-event").click(function(e) {
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length > 0) {
            $("#event-form").append('<input type="hidden" name="alert_uuids" value="' + all_alert_uuids.join(",") + '" />');
        }
    });

    $("#btn-realHours").click(function(e) {
        $("#frm-sla_hours").append('<input type="hidden" name="SLA_real-hours" value="1">').submit();
    });

    $("#btn-BusinessHours").click(function(e) {
        $("#frm-sla_hours").append('<input type="hidden" name="SLA_business-hours" value="1">').submit();
    });

    $("#btn-reset-filters").click(function(e) {
        $("#frm-filter").append('<input type="hidden" name="reset-filters" value="1">').submit();
    });

    // when the user clicks on the search button we just submit the filter dialog as-is
    // the filter dialog will be filled out with the current filter settings
    $("#btn-search").click(function(e) {
        $("#frm-filter").submit();
    });

    $("#btn-submit-comment").click(function(e) {
        // compile a list of all the alerts that are checked
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            alert("You must select one or more alerts to disposition.");
            return;
        }

        $("#comment-form").append('<input type="hidden" name="uuids" value="' + all_alert_uuids.join(",") + '" />');
        $("#comment-form").append('<input type="hidden" name="redirect" value="management" />');
        $("#comment-form").submit();
    });

    $("#btn-submit-tags").click(function(e) {
        $("#tag-form").submit();
    });

    $("#tag-form").submit(function(e) {
        // compile a list of all the alerts that are checked
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            alert("You must select one or more alerts to add tags to.");
            e.preventDefault();
            return;
        }

        $("#tag-form").append('<input type="hidden" name="uuids" value="' + all_alert_uuids.join(",") + '" />');
        $("#tag-form").append('<input type="hidden" name="redirect" value="management" />');
    });
});

$(document).ready(function() {
    if ($('input[name="daterange"]').val() == '') {
        $('input[name="daterange"]').val(
            moment().subtract(6, "days").startOf('day').format("MM-DD-YYYY HH:mm") + ' - ' +
            moment().format("MM-DD-YYYY HH:mm"));
    }

    $('input[name="remediate_daterange"]').daterangepicker({
        timePicker: true,
        format: 'MM-DD-YYYY HH:mm',
        startDate:  moment().subtract(6, 'days').startOf('day'),
        endDate: moment(),
        ranges: {
           'Today': [moment().startOf('day'), moment().endOf('day')],
           'Yesterday': [moment().subtract(1, 'days').startOf('day'), moment().subtract(1, 'days').endOf('day')],
           'Last 7 Days': [moment().subtract(6, 'days').startOf('day'), moment()],
           'Last 30 Days': [moment().subtract(29, 'days').startOf('day'), moment()],
           'This Month': [moment().startOf('month').startOf('day'), moment()],
           'Last Month': [moment().subtract(1, 'month').startOf('month').startOf('day'), moment().subtract(1, 'month').endOf('month').endOf('day')]
        }
    });

    $('input[name="daterange"]').daterangepicker({
        timePicker: true,
        format: 'MM-DD-YYYY HH:mm',
        startDate:  moment().subtract(6, 'days').startOf('day'),
        endDate: moment(),
        ranges: {
           'Today': [moment().startOf('day'), moment().endOf('day')],
           'Yesterday': [moment().subtract(1, 'days').startOf('day'), moment().subtract(1, 'days').endOf('day')],
           'Last 7 Days': [moment().subtract(6, 'days').startOf('day'), moment()],
           'Last 30 Days': [moment().subtract(29, 'days').startOf('day'), moment()],
           'This Month': [moment().startOf('month').startOf('day'), moment()],
           'Last Month': [moment().subtract(1, 'month').startOf('month').startOf('day'), moment().subtract(1, 'month').endOf('month').endOf('day')]
        }
    });

    if ($('input[name="disposition_daterange"]').val() == '') {
        $('input[name="disposition_daterange"]').val(
            moment().subtract(6, "days").format("MM-DD-YYYY HH:mm") + ' - ' + 
            moment().format("MM-DD-YYYY HH:mm"));
    }

    $('input[name="disposition_daterange"]').daterangepicker({
        timePicker: true,
        format: 'MM-DD-YYYY HH:mm',
        startDate:  moment().subtract(6, "days").startOf('day'),
        endDate: moment(),
        ranges: {
           'Today': [moment().startOf('day'), moment().endOf('day')],
           'Yesterday': [moment().subtract(1, 'days').startOf('day'), moment().subtract(1, 'days').endOf('day')],
           'Last 7 Days': [moment().subtract(6, 'days').startOf('day'), moment()],
           'Last 30 Days': [moment().subtract(29, 'days').startOf('day'), moment()],
           'This Month': [moment().startOf('month').startOf('day'), moment()],
           'Last Month': [moment().subtract(1, 'month').startOf('month').startOf('day'), moment().subtract(1, 'month').endOf('month').endOf('day')]
        }
    });

    // add event handlers to the column headers to trigger column sorting
    $("span[id^='sort_by_']").each(function(index) {
        var $this = $(this);
        $this.click(function(e) {
            //alert(this.id);
            sort_field = this.id.replace(/^sort_by_/, "");
            $("#frm-filter").append('<input type="hidden" name="sort_field" value="' + sort_field + '">');

            // was the user pressing shift? this indicates we want to add this column to the sort
            if (e.shiftKey) {
                $("#frm-filter").append('<input type="hidden" name="sort_field_add" value="1">');
            }

            // submit the form
            $("#frm-filter").submit();
        });
    });

    $("#btn-take-ownership").click(function(e) {
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            // XXX do this on the disposition button
            alert("You must select one or more alerts to disposition.");
            return;
        }

        // add a hidden field to the form
        $("#ownership-form").append('<input type="hidden" name="alert_uuids" value="' + all_alert_uuids.join(",") + '" />').submit();
    });

    $("#btn-assign-ownership").click(function(e) {
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            // XXX do this on the disposition button
            alert("You must select one or more alerts to assign to a user.");
            return;
        }

        // add a hidden field to the form and then submit
        $("#assign-ownership-form").append('<input type="hidden" name="alert_uuids" value="' + all_alert_uuids.join(",") + '" />').submit();
    });

    $("#btn-remediate-alerts").click(function(e) {
        var all_alert_uuids = get_all_checked_alerts();
        var message_ids = null;

        if (all_alert_uuids.length == 0 ) {
            // just prompt for the message_id
            var message_id = prompt("Enter a message_id to remediate.");
            if (message_id.length == 0) 
                return;

            message_ids = [message_id];
            all_alert_uuids = null;
        }

        remediate_emails(all_alert_uuids, message_ids);
    });

    $("#btn-phishfry-alerts").off()
    $("#btn-phishfry-alerts").click(function(e) {
        var all_alert_uuids = get_all_checked_alerts();

        if (all_alert_uuids.length == 0 ) {
            alert("You must select one or more alerts to remediate.");
            return;
        }

        remediate_alerts(all_alert_uuids);
    });

    $('#btn-limit').click(function(e) {
        result = prompt("How many alerts should be displayed at once?", 50);
    });
});

function new_alert_observable_type_changed(index) {
  var type_input = document.getElementById("observables_types_" + index);
  var value_input = document.getElementById("observables_values_" + index);
  if (type_input.value == 'file') {
    if (value_input.type != 'file') {
      value_input.parentNode.removeChild(value_input);
      $('#new_alert_observable_value_' + index).append('<input class="form-control" type="file" name="observables_values_' + index + '" id="observables_values_' + index + '" value="">');
    }
  } else if (value_input.type != 'text') {
    value_input.parentNode.removeChild(value_input);
    $('#new_alert_observable_value_' + index).append('<input class="form-control" type="text" name="observables_values_' + index + '" id="observables_values_' + index + '" value="">');
  }
}

function new_alert_remove_observable(index) {
  var element = document.getElementById("new_alert_observable_" + index);
  element.parentNode.removeChild(element);
}

// gets called when the user clicks on an observable link
function observable_link_clicked(observable_id) {
    $("#frm-filter").append('<input type="checkbox" name="observable_' + observable_id + '" CHECKED>').submit();
}

// gets called when the user clicks on a tag link
function tag_link_clicked(tag_id) {
    $("#frm-filter").append('<input type="checkbox" name="tag_' + tag_id + '" CHECKED>').submit();
}

// gets called when the user clicks on the right triangle button next to each alert
// this loads the observable information for the alerts and allows the user to select one for filtering
function load_alert_observables(alert_uuid) {
    // have we already loaded this?
    var existing_dom_element = $("#alert_observables_" + alert_uuid);
    if (existing_dom_element.length != 0) {
        existing_dom_element.remove();
        return;
    }

    $.ajax({
        dataType: "html",
        url: 'observables',
        data: { alert_uuid: alert_uuid },
        success: function(data, textStatus, jqXHR) {
            $('#alert_row_' + alert_uuid).after('<tr id="alert_observables_' + alert_uuid + '"><td colspan="6">' + data);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert("DOH: " + textStatus);
        }
    });
    
}

function change_limit(current_limit) {
    limit = prompt("How many alerts should be shown in the screen at once?", String(current_limit));
    if (limit == null) return;
    err = function() {
        alert("error: enter an integer value between 1 and 1000");
    };

    try {
        limit = parseInt(limit);
    } catch (e) {
        alert(e);
        return;
    }

    if (limit < 1 || limit > 1000) {
        err();
        return;
    }

    $("#frm-filter").append('<input type="hidden" name="modify_limit" value="' + limit.toString() + '"/>');
    $("#frm-filter").submit();
}

function navigate(direction) {
    $("#frm-filter").append('<input type="hidden" name="navigate" value="' + direction + '"/>');
    $("#frm-filter").submit();
}
