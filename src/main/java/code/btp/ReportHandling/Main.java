package code.btp.ReportHandling;

import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.util.Scanner;

/**
 * Main class.
 *
 */
public class Main {
    // Base URI the Grizzly HTTP server will listen on
    public static final String BASE_URI = "http://localhost:8080/";

    /**
     * Starts Grizzly HTTP server exposing JAX-RS resources defined in this application.
     * @return Grizzly HTTP server.
     */
    public static HttpServer startServer() {
        // create a resource config that scans for JAX-RS resources and providers
        // in code.btp.ReportHandling package
        final ResourceConfig rc = new ResourceConfig().packages("code.btp.ReportHandling");

        // create and start a new instance of grizzly http server
        // exposing the Jersey application at BASE_URI
        return GrizzlyHttpServerFactory.createHttpServer(URI.create(BASE_URI), rc);
    }

    /**
     * Main method.
     * @param args
     * @throws IOException
     */
    static HttpServer server;
    public static void main(String[] args) throws IOException {
        server = startServer();
        System.out.println(String.format("Jersey app started with WADL available at "
                + "%sapplication.wadl\n", BASE_URI));
        
        ReportManager manage =new ReportManager();
        UserInterface(manage);
        
        
    }

	public static void UserInterface(ReportManager manage) {
		
		Scanner scan =  new Scanner(System.in);
        String input="";
    	System.out.println("\n******\nType Your Query:- \n1. Stop\n2. AnalyseFeature");
    	
    	input = scan.nextLine();
    	if(input.compareToIgnoreCase("stop")==0 || input.compareToIgnoreCase("1")==0){
    		server.stop();
    		System.out.print("\033[H\033[2J");
    		System.out.flush();
    		System.out.println("Server Is Stopped");
    		return;
    	}
    	else if(input.compareToIgnoreCase("AnalyseFeature")==0 || input.compareToIgnoreCase("2")==0){
    		System.out.print("\033[H\033[2J");
    		System.out.flush();
    		System.out.println("Type Path to Json or ReportId ");
        	input = scan.nextLine();
        	System.out.println("want to \n1. Train \n2. Detect");
        	String type1=scan.nextLine();
        	if(type1.compareToIgnoreCase("1")==0){
        		type1="train";
        	}
        	else{
        		type1="detect";
        	}
        	System.out.println("Processing...");
        	//TODO reportid
        	JSONObject report = new ReportManager().AllFeatures(input,type1);
        	System.out.println("Processed");
        	System.out.println("want to save the current feature list? Y/N");
        	input = scan.nextLine();
        	if(input.compareToIgnoreCase("Y")==0){
        		manage.SaveCurrentFeature("CurrentFeatures");
        		System.out.println("feature list is saved  with filename CurrentFeatures.txt\n");
        	}
        	System.out.println("want to update AllFeatureDb? Y/N");
        	input = scan.nextLine();
        	if(input.compareToIgnoreCase("Y")==0){
        		manage.UpdateAllFeatures();;
        		System.out.println("AllFeatureDb is Updated..\n");
        	}
        	System.out.println("type\n1. InitializeTrainingData \n2. Initialize and add instance \n3. Add Instance to Training Data");
        	input = scan.nextLine();
        	if(input.compareToIgnoreCase("1")==0){
        		manage.InitializeData("train");
        		System.out.println("InitializeTrainingData done.. \n");
        	}
        	else if(input.compareToIgnoreCase("2")==0){
        		manage.InitializeData("train");
        		manage.AddAnInstanceOfData("train");
        		System.out.println("Initializes and added instance..\n");
        	}
        	else if(input.compareToIgnoreCase("3")==0){
        		manage.AddInstanceToData("train");
        		System.out.println("added instance..\n");
        	}
        	//TODO
        	manage.GenerateArffData("train");
        	
        	
    	}
    	else{
    		System.out.print("\033[H\033[2J");
    		System.out.flush();
    		System.out.println("you have Entered Query :- "+input);
    	}
    	UserInterface(manage);
		
	}
}

