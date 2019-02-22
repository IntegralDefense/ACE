//
// javascript functions for the analysis view
//

// this gets loaded when the document loads up
var current_alert_uuid = null;

$(document).ready(function() {
//$(window).load(function() {
    //debugger; // FREAKING AWESOME
    $("#add_observable_type").change(function(e) {
        const observable_type=$("#add_observable_type option:selected").text();
        if (observable_type!=="file") return;
        $("#add_observable_modal").modal("hide");
        $("#file_modal").modal("show");
    });

    $("#btn-submit-comment").click(function(e) {
        $("#comment-form").append('<input type="hidden" name="uuids" value="' + current_alert_uuid + '" />');
        $("#comment-form").append('<input type="hidden" name="redirect" value="analysis" />');
        $("#comment-form").submit();
    });

    $("#tag-form").submit(function(e) {
        $("#tag-form").append('<input type="hidden" name="uuids" value="' + current_alert_uuid + '" />');
        $("#tag-form").append('<input type="hidden" name="redirect" value="analysis" />');
    });

    $("#btn-submit-tags").click(function(e) {
        $("#tag-form").submit();
    });

    $("#btn-add-to-event").click(function(e) {
        $("#event-form").append('<input type="hidden" name="alert_uuids" value="' + current_alert_uuid + '" />');
    });

    //$('#btn-stats').click(function(e) {
        //e.preventDefault();
        /*var panel = $.jsPanel({
            position: "center",
            title: "Default Title",
            //content: $(".jsPanel-content"),
            size: { height: 270, width: 430 }
        });
        panel.on("jspanelloaded", function(event, id) {
            graph_alert($(".jsPanel-content")[0]);
        });*/

        //graph_alert($("#visualization")[0]);
    //});

    $('#btn-take-ownership').click(function(e) {
        $('#ownership-form').submit();
    });

    $('#btn-assign-ownership').click(function(e) {
        // add a hidden field to the form and then submit
        $("#assign-ownership-form").append('<input type="hidden" name="alert_uuid" value="' + current_alert_uuid + '" />').submit();
    });

    $("#btn-analyze_alert").click(function(e) {
        $('#analyze-alert-form').submit();
    });

    $("#btn-toggle-prune").click(function(e) {
        $('#toggle-prune-form').submit();
    });

    $("#btn-remediate-alerts").click(function(e) {
        remediate_emails([current_alert_uuid], null);
    });


    $("#btn-phishfry-alerts").off()
    $("#btn-phishfry-alerts").click(function(e) {
        remediate_alerts([current_alert_uuid]);
    });
    

    // pull this out of the disposition form
    current_alert_uuid = $("#alert_uuid").prop("value");
});

// attachment downloading
var $download_element;

function download_url(url) {
    if ($download_element) {
        $download_element.attr('src', url);
    } else {
        $download_element = $('<iframe>', { id: 'download_element', src: url }).hide().appendTo('body');
    }
}

function graph_alert(container) {
    $.ajax({
        dataType: "json",
        url: '/json',
        data: { alert_uuid: current_alert_uuid },
        success: function(data, textStatus, jqXHR) {
            var nodes = new vis.DataSet(data['nodes']);
            // create an array with edges
            var edges = new vis.DataSet(data['edges']);
            // create a network
            // this must be an actual DOM element
            //var container = $(".jsPanel-content")[0];
            var data = {
                nodes: nodes,
                edges: edges
            };
            var options = {
                nodes: {
                    shape: "dot",
                    size: 10 },
                layout: {
                    /*hierarchical: {
                        enabled: true,
                        sortMethod: 'directed'
                    }*/
                }
            };

            var network = new vis.Network(container, data, options);
            network.stopSimulation();
            network.stabilize();

            // turn off the physics engine once it's stabilized
            network.once("stabilized", function() {
                // don't let it run stabilize again
                network.on("startStabilizing", function() {
                    network.stopSimulation();
                });

                //network.setOptions({
                    //physics: { enabled: false }
                //});
                network.fit();
            });

            network.on("click", function() {
            });

            network.on("resize", function() {
                network.fit();
            });
    
            network.on("selectNode", function(e) {
                for (var i = 0; i < e.nodes.length; i++) {
                    var node = data.nodes.get(e.nodes[i]);
                    if ('details' in node) {
                        data.nodes.update({id: node.id, label: node.details, saved_label: node.label, font: { background: 'white' }});
                    }

                    if ('observable_uuid' in node && 'module_path' in node) {
                        var new_window = window.open("/analysis?observable_uuid=" + node.observable_uuid + "&module_path=" + encodeURIComponent(node.module_path), "");
                        if (new_window) { } else { alert("Unable to open a new window (adblocker?)"); }
                    }
                }
            });

            network.on("deselectNode", function(e) {
                for (var i = 0; i < e.previousSelection.nodes.length; i++) {
                    var node = data.nodes.get(e.previousSelection.nodes[i]);
                    if ('details' in node) {
                        data.nodes.update({id: node.id, label: node.saved_label});
                    }
                }
            });

            $("#btn-fit-to-window").click(function(e) {
                network.fit();
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert("DOH");
        }
    });
}

function delete_comment(comment_id) {
    if (! confirm("Delete comment?")) 
        return;

    try {
        $("#comment_id").val(comment_id.toString());
    } catch (e) {
        alert(e);
        return;
    }

    $("#delete_comment_form").submit();
}
