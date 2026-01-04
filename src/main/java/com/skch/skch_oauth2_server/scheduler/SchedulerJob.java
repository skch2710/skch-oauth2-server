package com.skch.skch_oauth2_server.scheduler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.skch.skch_oauth2_server.dao.UsersDAO;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@EnableScheduling
public class SchedulerJob {
	
	@Autowired
	private UsersDAO usersDao;
	
	/**
	 * Scheduled task to clean up expired tokens.
	 * Runs at Every Saturday and Sunday at 1:00 AM.
	 */
	@Scheduled(cron = "${scheduler.cleanup-expired-tokens}")
	public void cleanupExpiredTokens() {
		log.info("Starting cleanup of expired tokens...");
		
		usersDao.clearExpiredTokens();
		
		log.info("Ending cleanup of expired tokens...");
	}

}
