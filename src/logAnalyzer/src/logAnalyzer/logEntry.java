package logAnalyzer;

public class logEntry {
	
	private String timeStamp;
	private String user;
	private String ip;
	private String status;

	public logEntry(String timeStamp, String user, String ip, String status ) {
		this.timeStamp = timeStamp;
		this.user = user;
		this.ip = ip;
		this.status = status;
	}
    public String getTimestamp() {
        return timeStamp;
    }

    public String getUser() {
        return user;
    }

    public String getIp() {
        return ip;
    }

    public String getStatus() {
        return status;
    }
	
}
