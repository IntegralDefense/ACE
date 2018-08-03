function load_event_alerts(event_id) {
    // have we already loaded this?
    var existing_dom_element = $("#event_alerts_" + event_id);
    if (existing_dom_element.length != 0) {
        existing_dom_element.remove();
        return;
    }

    $.ajax({
        dataType: "html",
        url: 'event_alerts',
        data: { event_id: event_id },
        success: function(data, textStatus, jqXHR) {
            $('#event_row_' + event_id).after(data);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert("DOH: " + textStatus + " - " + errorThrown);
        }
    });
}

function get_all_checked_event_mappings() {
    // returns the list of all checked event_alet mappings
    var result = Array();
    $("input[name^='detail_']").each(function(index) {
        var $this = $(this);
        if ($this.is(":checked")){
            result.push($this.prop("name").replace(/^detail_/, ""));
        } 
    });

    return result;
}

function edit_event(event_id) {
    // have we already loaded this?
    var existing_dom_element = $("#new_event_dialog");
    if (existing_dom_element.length != 0) {
        existing_dom_element.remove();
    }

    $.ajax({
        dataType: "html",
        url: 'edit_event_modal',
        data: { event_id: event_id },
        success: function(data, textStatus, jqXHR) {
            $('#edit_event_insert').after(data);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert("DOH: " + textStatus);
        }
    });

    $("#edit_event_modal").modal("show");
}

$(document).ready(function() {
    $('input[name="event_daterange"]').daterangepicker({
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

    $("#btn-remove-alerts").click(function(e) {
        // compile a list of all the alerts that are checked
        mappings = get_all_checked_event_mappings();
        if (mappings.length == 0) {
            alert("You must select one or more alerts to remove.");
            return;
        }

        // add mappings to the form and submit
        $("#remove-alerts-form").append('<input type="hidden" name="event_mappings" value="' + mappings.join(",") + '" />').submit();
    });

    $("#btn-reset-filters").click(function(e) {
        $("#frm-filter").append('<input type="hidden" name="reset-filters" value="1">').submit();
    });

    $("#btn-search").click(function(e) {
        $("#frm-filter").submit();
    });

    // add event handlers to the column headers to trigger column sorting
    $("span[id^='sort_by_']").each(function(index) {
        var $this = $(this);
        $this.click(function(e) {
            sort_field = this.id.replace(/^sort_by_/, "");
            $("#frm-filter").append('<input type="hidden" name="sort_field" value="' + sort_field + '">');
            $("#frm-filter").submit();
        });
    });
});
