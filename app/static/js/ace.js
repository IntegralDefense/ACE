// Alert Correlation Engine
// 

$(document).ready(function() {
    $("#event-form").on("submit", function(e) {
        e.preventDefault();
        var event_name_re = /^[a-zA-Z0-9+-. ]+$/;
        event_name = $("#event_name").val();
        if (event_name != "" && ! event_name_re.test(event_name)) {
            alert("Event names can only have the characters a-Z A-Z 0-9 + - . and space.");
            return;
        }

        this.submit();
    });
});

function toggleNewEventDialog() {
  if (document.getElementById("option_NEW").checked) {
    document.getElementById("new_event_dialog").style.display = 'block';
  }
  else {
    document.getElementById("new_event_dialog").style.display = 'none';
  }
}

function toggleNewCampaignInput() {
  if (document.getElementById("campaign_id").value == 'NEW') {
    document.getElementById("new_campaign").style.display = 'block';
  }
  else {
    document.getElementById("new_campaign").style.display = 'none';
  }
}

function new_malware_option() {
  var index = new Date().valueOf()
  $.ajax({
    dataType: "html",
    url: 'new_malware_option',
    data: {index: index},
    success: function(data, textStatus, jqXHR) {
      $('#new_event_dialog').append(data);
    },
    error: function(jqXHR, textStatus, errorThrown) {
      alert("DOH: " + textStatus);
    }
  });
}

function remove_malware_option(index) {
  var element = document.getElementById("malware_option_" + index);
  element.parentNode.removeChild(element);
}

function malware_selection_changed(index) {
  var element = document.getElementById("malware_selection_" + index);
  if (element.value == 'NEW') {
    document.getElementById("new_malware_info_" + index).style.display = 'block';
  }
  else {
    document.getElementById("new_malware_info_" + index).style.display = 'none';
  }
}

