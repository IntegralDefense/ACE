DELETE FROM analysis_results WHERE insert_date < NOW() - INTERVAL 7 DAY;
