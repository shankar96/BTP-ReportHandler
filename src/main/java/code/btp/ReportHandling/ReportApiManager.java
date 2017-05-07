package code.btp.ReportHandling;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Scanner;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import org.json.JSONObject;

@Path("report")
public class ReportApiManager {
	
	@GET
	@Path("UpdateAllFeatures")
    @Produces(MediaType.APPLICATION_JSON)
    public String UpdateAllFeatures(@QueryParam("id") String id1) {
		ReportManager manage = new ReportManager();
    	System.out.println("Updating AllFeatures....");
    	int id=1;
    	if(id1!=null)
    		id=Integer.parseInt(id1);
    	System.out.println("starting from id "+id);
    	while(true)
    	{
			JSONObject report = GetReportByIdFromCuckoo(manage, id);
    		//saveUrl(id);
    		//JSONObject report = loadJson();
			if(report.has("info")){
				System.out.println(report.getJSONObject("info"));
				System.out.println("Extracting features....");
				manage.ExtractFeatures(report,"train");
				System.out.println("updating features...");
				manage.UpdateAllFeatures();
				
				
			}
			else{
				break;
			}
			System.out.println("***done****\n");
			id++;
    	}
		
    	System.out.println("\n******\nType Your Query:- \n1. Stop\n2. AnalyseFeature");
        return "AllFeatures is Updated";
    }
	
	
	@GET
	@Path("TrainTestData")
    @Produces(MediaType.APPLICATION_JSON)
    public String UpdateDataSet(@QueryParam("InitializeData") String InitializeData,
    		@QueryParam("ReportId") String ReportId,
    		@QueryParam("Train") String Train,
    		@QueryParam("Detect") String Detect,
    		@QueryParam("From") String From,
    		@QueryParam("To") String To
    		) {
		String response="";
		ReportManager manage = new ReportManager();
		System.out.println("Queryparameter....\n"+"InitializeData-"+InitializeData+"\n"+
				"ReportId-"+ReportId+"\n"+
				"Train-"+Train+"\n"+
				"Detect-"+Detect+"\n"+
				"From-"+From+"\n"+
				"To-"+To+"\n"+
				"");
		
		if(InitializeData!=null && InitializeData.compareToIgnoreCase("yes")==0){
			if( Detect!=null && Detect.compareToIgnoreCase("yes")==0 && (Train==null || (Train!=null && Train.compareToIgnoreCase("no")==0) )  ){
				manage.InitializeData("test");
				manage.GenerateArffData("test");
				response=response+"testing DataSets Are Initialized...\n";
			}
			else{
				manage.InitializeData("train");
				manage.InitializeData("test");
				manage.GenerateArffData("train");
				manage.GenerateArffData("test");
				response=response+"training and testing DataSets Are Initialized...\n";
			}
			
			
		}
		if(ReportId!=null && Train!=null && Train.compareToIgnoreCase("yes")==0 && ReportId.matches("[0-9]+")){
			JSONObject report = GetReportByIdFromCuckoo(manage, Integer.parseInt(ReportId));
			if(report.has("info")){
				manage.ExtractFeatures(report,"train");
				manage.AddAnInstanceOfData("train");
				response=response+"An instance From ReportId ("+ReportId+") Is Added to DataSets...\n";
			}
			else{
				response=response+"********\nError In Report ReportId="+ReportId+"\n**********\n";
			}
		}
		if(ReportId!=null && Detect!=null && Detect.compareToIgnoreCase("yes")==0 && ReportId.matches("[0-9]+")){
			JSONObject report = GetReportByIdFromCuckoo(manage, Integer.parseInt(ReportId));
			if(report.has("info")){
				manage.ExtractFeatures(report,"test");
				manage.AddAnInstanceOfData("test");
				response=response+"An instance From ReportId ("+ReportId+") Is Added to DataSets...\n";
			}
			else{
				response=response+"********\nError In Report ReportId="+ReportId+"\n**********\n";
			}
		}
		if(Train!=null && From!=null && To!=null && Train.compareToIgnoreCase("yes")==0 && From.matches("[0-9]+") && To.matches("[0-9]+")){
			response=response+"Processing Instances From ReportId ("+From+") To ReportId ("+To+")\n";
			for(int i=Integer.parseInt(From);i<=Integer.parseInt(To);i++){
				JSONObject report = GetReportByIdFromCuckoo(manage, i);
				if(report.has("info")){
					manage.ExtractFeatures(report,"train");
					manage.AddAnInstanceOfData("train");
					response=response+"An instance From ReportId ("+i+") Is Added to DataSets...\n";
				}
				else{
					response=response+"********\nError In Report ReportId="+i+"\n**********\n";
				}
			}
			
		}
		if(Detect!=null && From!=null && To!=null && Detect.compareToIgnoreCase("yes")==0 && From.matches("[0-9]+") && To.matches("[0-9]+")){
			response=response+"Processing Instances From ReportId ("+From+") To ReportId ("+To+")\n";
			for(int i=Integer.parseInt(From);i<=Integer.parseInt(To);i++){
				JSONObject report = GetReportByIdFromCuckoo(manage, i);
				if(report.has("info")){
					manage.ExtractFeatures(report,"test");
					manage.AddAnInstanceOfData("test");
					response=response+"An instance From ReportId ("+i+") Is Added to DataSets...\n";
				}
				else{
					response=response+"********\nError In Report ReportId="+i+"\n**********\n";
				}
			}
			
		}
		
    	System.out.println("\n******\nType Your Query:- \n1. Stop\n2. AnalyseFeature");
		response=response+"\nHow to Use?\nProvide Following as query\n"
				+"InitializeData=yes/no \n"
				+"ReportId=idnumber  && Train=yes/no \n"
				+"ReportId=idnumber && Detect=yes/no \n"
				+"From=startid && To=endid && Train=yes/no";
		
		return response;
	}
	
	
	
	//API Helping Codes..
	public static JSONObject GetReportByIdFromCuckoo(ReportManager manage, int id){
		String urlString = "http://localhost:8090/tasks/report/"+id;
		try{
			URL url = new URL(urlString);
			
			HttpURLConnection.setFollowRedirects(false);
			HttpURLConnection con = (HttpURLConnection) url.openConnection();
			 
			// By default it is GET request
			con.setRequestMethod("GET");
			con.setConnectTimeout(90000); //set timeout to 5 minute

			//add request header
			//con.setRequestProperty("User-Agent", USER_AGENT);
			 
			int responseCode = con.getResponseCode();
			System.out.println("Sending get request : "+ url);
			System.out.println("Response code : "+ responseCode);
			 
			// Reading response from input Stream
			BufferedReader in = new BufferedReader(
			        new InputStreamReader(con.getInputStream()));
			String output;
			StringBuffer response = new StringBuffer();
			
			int i=0,k=0;
			while ((output = in.readLine()) != null) {
				if(i%1000000==0){
					System.out.println("->i"+k);
					k++;
					i=0;
				}
				i++;
				response.append(output);
			}
			
			
			in.close();
			
			//printing result from response
			JSONObject report = new JSONObject(response.toString());
			System.out.println("report Generated");
			return report;
			
		}
		
		catch (java.net.SocketTimeoutException e) {
			System.out.println("error in APi "+e+"\n");
			return new JSONObject();
		} catch (java.io.IOException e) {
			System.out.println("error in APi "+e+"\n");
			return new JSONObject();
		}
		catch(Exception e){
			System.out.println("error in APi "+e+"\n");
			return new JSONObject();
		}
	}
	
	static String TempReport = "TempReport.json";
	public static JSONObject loadJson(){
		System.out.println("loading temp report...");
		JSONObject report = new JSONObject();
		try (Scanner s = new Scanner(TempReport).useDelimiter("\\Z")) {
		      return new JSONObject(s.next());
		}
		catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
			return new JSONObject();
		}
		
		
	}
	public static void saveUrl(int id) {
		String urlString ="http://localhost:8090/tasks/report/"+id;
		System.out.println("saving temp report....");
		
	    BufferedInputStream in = null;
	    FileOutputStream fout = null;
	    try {
	        in = new BufferedInputStream(new URL(urlString).openStream());
	        fout = new FileOutputStream(TempReport);

	        final byte data[] = new byte[1024];
	        int count;
	        while ((count = in.read(data, 0, 1024)) != -1) {
	            fout.write(data, 0, count);
	        }
	    } catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			try{
		        if (in != null) {
		            in.close();
		        }
		        if (fout != null) {
		            fout.close();
		        }
			}
			catch(Exception e){
				e.printStackTrace();
			}
	    }
	}
	
	

}
