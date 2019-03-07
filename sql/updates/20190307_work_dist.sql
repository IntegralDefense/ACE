ALTER TABLE `ace`.`work_distribution` 
CHANGE COLUMN `status` `status` ENUM('READY', 'COMPLETED', 'ERROR') NOT NULL DEFAULT 'READY' COMMENT 'The status of the submission. Defaults to READY until the work has been submitted. \nOn a successful submission the status changes to COMPLETED.\nIf an error is detected, the status will change to ERROR.' ;

