ALTER TABLE `alerts` 
DROP INDEX `idx_location` ,
ADD INDEX `idx_location` (`location`(767) ASC);

ALTER TABLE `alerts` CHANGE COLUMN `uuid` `uuid` VARCHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NOT NULL ,
 CHANGE COLUMN `storage_dir` `storage_dir` VARCHAR(512) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ,
 CHANGE COLUMN `tool` `tool` VARCHAR(256) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ,
 CHANGE COLUMN `tool_instance` `tool_instance` VARCHAR(1024) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ,
 CHANGE COLUMN `alert_type` `alert_type` VARCHAR(64) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ,
 CHANGE COLUMN `description` `description` VARCHAR(1024) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NULL DEFAULT NULL ,
 CHANGE COLUMN `lock_owner` `lock_owner` VARCHAR(256) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NULL DEFAULT NULL ,
 CHANGE COLUMN `lock_id` `lock_id` VARCHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NULL DEFAULT NULL ,
 CHANGE COLUMN `lock_transaction_id` `lock_transaction_id` VARCHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NULL DEFAULT NULL ,
 CHANGE COLUMN `location` `location` VARCHAR(1024) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ;

ALTER TABLE `campaign` CHANGE COLUMN `name` `name` VARCHAR(128) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ;

ALTER TABLE `cloudphish_analysis_results` CHANGE COLUMN `http_message` `http_message` VARCHAR(256) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NULL DEFAULT NULL COMMENT 'The message text that came along with the http_result_code.' ,
CHANGE COLUMN `uuid` `uuid` VARCHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NOT NULL COMMENT 'The UUID of the analysis. This would also become the UUID of the alert if it ends up becoming one.' ;

ALTER TABLE `cloudphish_content_metadata` 
CHANGE COLUMN `node` `node` VARCHAR(1024) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NULL DEFAULT NULL COMMENT 'The name of the node which stores this binary data. This would match the name columns of the nodes table, however, there is not a database relationship because the nodes can change.' ,
CHANGE COLUMN `name` `name` VARBINARY(4096) NOT NULL COMMENT 'The name of the file as it was seen either by content disposition of extrapolated from the URL.\nThis is stored in python’s “unicode_internal” format.' ;

ALTER TABLE `cloudphish_url_lookup` 
CHANGE COLUMN `url` `url` TEXT CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL COMMENT 'The value of the URL.' ;

ALTER TABLE `comments` 
CHANGE COLUMN `uuid` `uuid` VARCHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NOT NULL ,
CHANGE COLUMN `comment` `comment` TEXT CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ;

ALTER TABLE `company` 
CHANGE COLUMN `name` `name` VARCHAR(128) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ;

ALTER TABLE `delayed_analysis` 
CHANGE COLUMN `uuid` `uuid` VARCHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NOT NULL ,
CHANGE COLUMN `observable_uuid` `observable_uuid` CHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NOT NULL ,
CHANGE COLUMN `analysis_module` `analysis_module` VARCHAR(512) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ,
CHANGE COLUMN `exclusive_uuid` `exclusive_uuid` VARCHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NULL DEFAULT NULL COMMENT 'A workload item with an exclusive lock will only be processed by the engine (node) that created it.' ,
CHANGE COLUMN `storage_dir` `storage_dir` VARCHAR(1024) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL COMMENT 'The location of the analysis. Relative paths are relative to SAQ_HOME.' ;

ALTER TABLE `events` 
CHANGE COLUMN `name` `name` VARCHAR(128) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ,
CHANGE COLUMN `comment` `comment` TEXT CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NULL DEFAULT NULL ;

ALTER TABLE `incoming_workload` 
CHANGE COLUMN `mode` `mode` VARCHAR(256) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL COMMENT 'The analysis mode the work will be submit with. This determines what nodes are selected for receiving the work.' ;

ALTER TABLE `incoming_workload_type` 
CHANGE COLUMN `name` `name` VARCHAR(512) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL COMMENT 'The name of the work (http, email, etc…)' ;

ALTER TABLE `locks` 
CHANGE COLUMN `uuid` `uuid` VARCHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NOT NULL ,
CHANGE COLUMN `lock_uuid` `lock_uuid` VARCHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NULL DEFAULT NULL ,
CHANGE COLUMN `lock_owner` `lock_owner` VARCHAR(512) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NULL DEFAULT NULL ;

ALTER TABLE `malware` 
CHANGE COLUMN `name` `name` VARCHAR(128) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ;

ALTER TABLE `node_modes` 
CHANGE COLUMN `analysis_mode` `analysis_mode` VARCHAR(256) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL COMMENT 'The analysis_mode that this mode will support processing.' ;

ALTER TABLE `nodes` 
DROP INDEX `node_UNIQUE` ,
ADD UNIQUE INDEX `node_UNIQUE` (`name`(767) ASC);

ALTER TABLE `nodes` 
CHANGE COLUMN `name` `name` VARCHAR(1024) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL COMMENT 'The value of SAQ_NODE in the [global] section of the configuration file.' ,
CHANGE COLUMN `location` `location` VARCHAR(1024) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL COMMENT 'Also called the API_PREFIX, this is the hostname:port portion of the URL for the api for the node.' ;

ALTER TABLE `observables` 
ADD COLUMN `md5` VARBINARY(16) NULL AFTER `value`,
ADD UNIQUE INDEX `i_type_md5` (`type` ASC, `md5` ASC),
DROP INDEX `index_type_value` ;

ALTER TABLE `observables` 
CHANGE COLUMN `type` `type` VARCHAR(64) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ,
CHANGE COLUMN `value` `value` BLOB NOT NULL ;

UPDATE `observables` SET `md5` = UNHEX(MD5(`value`));

ALTER TABLE `observables` 
CHANGE COLUMN `md5` `md5` VARBINARY(16) NOT NULL;

ALTER TABLE `remediation` 
CHANGE COLUMN `key` `key` VARCHAR(256) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL COMMENT 'The key to look up the item.  In the case of emails this is the message_id and the recipient email address.' ,
CHANGE COLUMN `result` `result` TEXT CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NULL DEFAULT NULL COMMENT 'The result of the action.  This is free form data for the analyst to see, usually includes error codes and messages.' ,
CHANGE COLUMN `comment` `comment` TEXT CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NULL DEFAULT NULL COMMENT 'Optional comment, additional free form data.' ;

ALTER TABLE `tags` 
CHANGE COLUMN `name` `name` VARCHAR(256) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ;

ALTER TABLE `users` 
CHANGE COLUMN `username` `username` VARCHAR(64) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ,
CHANGE COLUMN `email` `email` VARCHAR(64) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ,
CHANGE COLUMN `timezone` `timezone` VARCHAR(512) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NULL DEFAULT NULL COMMENT 'The timezone this user is in. Dates and times will appear in this timezone in the GUI.' ;

ALTER TABLE `work_distribution_groups` 
CHANGE COLUMN `name` `name` VARCHAR(128) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL COMMENT 'The name of the group (Production, QA, etc…)' ;

ALTER TABLE `workload` 
CHANGE COLUMN `uuid` `uuid` VARCHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NOT NULL ,
CHANGE COLUMN `analysis_mode` `analysis_mode` VARCHAR(256) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL ,
CHANGE COLUMN `exclusive_uuid` `exclusive_uuid` VARCHAR(36) CHARACTER SET 'ascii' COLLATE 'ascii_general_ci' NULL DEFAULT NULL COMMENT 'A workload item with an exclusive lock will only be processed by the engine (node) that created it.' ,
CHANGE COLUMN `storage_dir` `storage_dir` VARCHAR(1024) CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_520_ci' NOT NULL COMMENT 'The location of the analysis. Relative paths are relative to SAQ_HOME.' ;

DROP TABLE `pp_alert_mapping`;
DROP TABLE `pp_tag_mapping`;
DROP TABLE `profile_points`;
