package logAnalyzer;

import java.util.Vector;

public class printer {
	
	public void printReports(Vector<Suspicious> Suspicious) {
		if(Suspicious == null || Suspicious.isEmpty()) {
			System.out.println("No suspicious attempts");
			return;
		} else { 
			for (Suspicious s : Suspicious) {
				System.out.println("Suspicous IP: " + s.getIp()); 
				System.out.println( "failed attempts: "+ s.getFailCount() );
				System.out.println("username: "+ s.getUsers().toString());
				System.out.println( "first attempt: "+ s.getFirstTS());
				System.out.println( "last attempt: " + s.getLastTS());
				System.out.println("-------");
			}
		}	
	}
}
