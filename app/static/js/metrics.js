function js_download(dataframe) {
    // download table results to csv file on client side
    var csv = '%s';

    var filename = dataframe.name + '.csv' ;
    //https://stackoverflow.com/questions/31893930/download-csv-from-an-ipython-notebook
}

$(document).ready(function() {
    if ($('input[name="daterange"]').val() == '') {
        $('input[name="daterange"]').val(
            moment().subtract(6, "days").startOf('day').format("MM-DD-YYYY HH:mm:ss") + ' - ' +
            moment().format("MM-DD-YYYY HH:mm:ss"));
    }

    $('input[name="daterange"]').daterangepicker({
        timePicker: true,
        format: 'MM-DD-YYYY HH:mm:ss',
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

});

