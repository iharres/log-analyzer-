package logAnalyzer;

import java.util.Vector;

public class Suspicious {
	private String ip;
	private Vector<String> users;
	private int failCount;
	private String firstTs;
	private String lastTs;
	
	public Suspicious(String ip) {
		this.ip = ip;
		this.users = new Vector<>();
		this.failCount = 0;
		this.firstTs = null;
		this.lastTs = null;
	}
	
	public void add(logEntry e) {
		failCount++;
		
		String user = e.getUser();
		if(!containsUser(user)) {
			users.add(user);
		}
		
		String timeStamp = e.getTimestamp();
		if(firstTs == null) {
			firstTs = timeStamp;
		}
		lastTs = timeStamp;
	}
	
	public boolean containsUser(String user) {
        for (String users : users) {
    		if(users.equals(user)) {
            	return true;
            }
        }
        return false;
	}
	
    public String getIp() {
        return ip;
    }

    public int getFailCount() {
        return failCount;
    }

    public Vector<String> getUsers() {
        return users;
    }

    public String getFirstTS() {
        return firstTs;
    }

    public String getLastTS() {
        return lastTs;
    }
	
	
}
