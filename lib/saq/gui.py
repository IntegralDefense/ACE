# vim: sw=4:ts=4:et:cc=120
#
# contains classes and routines for the ACE GUI
#

import logging

import saq
from saq.constants import *
from saq.database import Alert

import pytz

__all__ = [ 
    'GUIAlert',
    'ObservableActionSeparator',
    'ObservableActionUploadToCrits',
    'ObservableActionDownloadFile',
    'ObservableActionDownloadFileAsZip',
    'ObservableActionViewAsHex',
    'ObservableActionViewAsText',
    'ObservableActionUploadToVt',
    'ObservableActionUploadToVx',
    'ObservableActionViewInVt',
    'ObservableActionViewInVx',
    'ObservableActionCollectFile',
    'ObservableActionClearCloudphishAlert',
    'ObservableActionRemediateEmail',
    'ObservableActionWhitelist',
    'ObservableActionUnWhitelist',
]
    

class GUIAlert(Alert):

    def _initialize(self, *args, **kwargs):
        super()._initialize(*args, **kwargs)

        # the timezone we use to display datetimes, defaults to UTC
        self.display_timezone = pytz.utc

    """Extends the Alert class to add functionality specific to the GUI."""
    @property
    def jinja_template_path(self):
        # have a specified a template for this alert type?
        try:
            logging.debug("checking for custom template for {}: {}".format(
                          self.alert_type, saq.CONFIG.get('custom_alerts', self.alert_type)))
            return saq.CONFIG.get('custom_alerts', self.alert_type)
        except:
            pass

        # otherwise just return the default
        return "analysis/alert.html"

    @property
    def jinja_analysis_overview(self):
        result = '<ul>'
        for observable in self.observables:
            result += '<li>{0}</li>'.format(observable)
        result += '</ul>'

        return result

    @property
    def jinja_event_time(self):
        return self.event_time.strftime(event_time_format_tz)

    @property
    def display_insert_date(self):
        """Returns the insert date in the timezone specified by display_timezone."""
        return self.insert_date.astimezone(self.display_timezone).strftime(event_time_format_tz)

    @property
    def display_disposition_time(self):
        """Returns the disposition time in the timezone specified by display_timezone."""
        return self.disposition_time.astimezone(self.display_timezone).strftime(event_time_format_tz)

    @property
    def display_event_time(self):
        """Returns the time the alert was observed (which may be different from when the alert was inserted
           into the database."""
        return self.event_time.astimezone(self.display_timezone).strftime(event_time_format_tz)

class ObservableAction(object):
    """Represents an "action" that a user can take with an Observable in the GUI."""
    def __init__(self):
        self.name = None
        self.description = None
        self.jinja_action_path = None
        self.icon = None

class ObservableActionSeparator(ObservableAction):
    """Use this to place separator bars in your list of action choices."""
    pass

class ObservableActionUploadToCrits(ObservableAction):
    """Action to upload the given observable as an indicator to crits."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_UPLOAD_TO_CRITS
        self.description = "Upload To CRITS"
        self.jinja_action_path = 'analysis/observable_actions/upload_to_crits.html'
        self.icon = 'cloud-upload'

class ObservableActionClearCloudphishAlert(ObservableAction):
    """Action to clear the cached cloudphish alert for this url."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_CLEAR_CLOUDPHISH_ALERT
        self.description = "Clear Cloudphish Alert"
        self.jinja_action_path = 'analysis/observable_actions/clear_cloudphish_alert.html'
        self.icon = 'thumbs-down'

class ObservableActionRemediateEmail(ObservableAction):
    """Action to remediate a given email (referenced by message-id)."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_REMEDIATE_EMAIL
        self.description = "Remediate Email"
        self.jinja_action_path = 'analysis/observable_actions/remediate_email.html'
        self.icon = 'remove'

class ObservableActionDownloadFile(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_DOWNLOAD
        self.description = "Download File"
        self.jinja_action_path = 'analysis/observable_actions/download_file.html'
        self.icon = 'download-alt'

class ObservableActionDownloadFileAsZip(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_DOWNLOAD_AS_ZIP
        self.description = "Download File As ZIP"
        self.jinja_action_path = 'analysis/observable_actions/download_file_as_zip.html'
        self.icon = 'download-alt'

class ObservableActionViewAsHex(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_AS_HEX
        self.description = "View As Hex"
        self.jinja_action_path = 'analysis/observable_actions/view_as_hex.html'
        self.icon = 'zoom-in'

class ObservableActionViewAsText(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_AS_TEXT
        self.description = "View As Text"
        self.jinja_action_path = 'analysis/observable_actions/view_as_text.html'
        self.icon = 'file'

class ObservableActionUploadToVt(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_UPLOAD_VT
        self.description = "Upload To VirusTotal"
        self.jinja_action_path = 'analysis/observable_actions/upload_to_vt.html'
        self.icon = 'export'

class ObservableActionUploadToVx(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_UPLOAD_VX
        self.description = "Upload To VxStream"
        self.jinja_action_path = 'analysis/observable_actions/upload_to_vx.html'
        self.icon = 'export'

class ObservableActionViewInVt(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_VT
        self.description = "View In VirusTotal"
        self.jinja_action_path = 'analysis/observable_actions/view_in_vt.html'
        self.icon = 'chevron-right'

class ObservableActionViewInVx(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_VX
        self.description = "View In VxStream"
        self.jinja_action_path = 'analysis/observable_actions/view_in_vx.html'
        self.icon = 'chevron-right'

class ObservableActionCollectFile(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_COLLECT_FILE
        self.description = "Collect File"
        self.jinja_action_path = 'analysis/observable_actions/collect_file.html'
        self.icon = 'save-file'

class ObservableActionWhitelist(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_WHITELIST
        self.description = "Whitelist"
        self.jinja_action_path = 'analysis/observable_actions/whitelist.html'
        self.icon = 'ok'

class ObservableActionUnWhitelist(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_UN_WHITELIST
        self.description = "Un-Whitelist"
        self.jinja_action_path = 'analysis/observable_actions/un_whitelist.html'
        self.icon = 'remove'
