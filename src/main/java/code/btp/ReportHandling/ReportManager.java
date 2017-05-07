package code.btp.ReportHandling;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.Vector;

import javax.print.DocFlavor.STRING;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class ReportManager {
	
	static HashMap<String,Integer> AllFeaturesDB = null;//(feature_name) (id)  (number of sample having this feature) 
	static TreeMap<Integer,String> SortedAllFeaturesDB= new TreeMap<>();
	static HashMap<String,FDetail> CurrentFeatures = new HashMap<String,FDetail>(); //(feature_name) (current_id) (number of this feature in this sample)
	static String[] MalwareTypes ={"adware","spyware","virus","worm","trojan","rootkit","backdoor","keylogger","ransomware","Hijacker","spam","unknown"};
	
	//filename
	final static String AllFeaturesDBtxt = "AllFeaturesDB.txt";
	final static String MalwareTypeVirustotaltxt = "MalwareTypeVirustotal.txt";
	final static String AllTrainDatatxt = "AllTrainData.txt";
	final static String AllTestDatatxt ="AllTestData.txt";
	final static String MacroFormatarff = "FormatMacro.arff";
	final static String MicroFormatarff = "FormatMicro.arff";
	final static String MalwareDetectionTrainDataSetsarff = "MalwareDetectionTrainDataSets.arff";
	final static String MalwareClassificationTrainDataSetsarff ="MalwareClassificationTrainDataSets.arff";
	final static String MalwareDetectionTestDataSetsarff = "TestIsMalware.arff";
	final static String MalwareClassificationTestDataSetsarff ="TestMalwareType.arff";
	
	public ReportManager() {
		if(AllFeaturesDB==null){
			AllFeaturesDB=new HashMap<>();
			System.out.println("loading data....");
			// TODO Loading Database
			try {
				BufferedReader br = new BufferedReader(new FileReader(AllFeaturesDBtxt));
				try {
					String line =br.readLine();
					while(line!=null){
						if(line.length()>0){
							String str[] = line.split("\t");
							AllFeaturesDB.put(str[1], Integer.parseInt(str[0]));
						}
						line=br.readLine();
						
					}
					br.close();
					SortedAllFeaturesDB=SortById_AllFeature(AllFeaturesDB);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else{
			System.out.println("AllFeaturesdb loaded already.."+AllFeaturesDB.size()+", "+SortedAllFeaturesDB.size());
		}
		
	}
	public JSONObject AllFeatures(String path, String type) {
    	System.out.println("Feature Extraction");
		try {
			 
			 JSONObject report = parseJSONFile(path);
			 ExtractFeatures(report,type);
			 return report;
		}
		catch (JSONException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return new JSONObject("{}");
		}
        
    }
	int CurrentId=0;
	public  void ExtractFeatures(JSONObject report,String Type_Train_Detect) {
		// TODO Auto-generated method stub
		System.out.println("resetting CurrentFeatures..."+CurrentFeatures.size());
		CurrentFeatures.clear();
		CurrentId = 0;
		System.out.println("resetted CurrentFeatures..."+CurrentFeatures.size());
		String filename="";
		//Training filename use for known info type
		 if(report.has("target") && report.getJSONObject("target").has("file") && report.getJSONObject("target").getJSONObject("file").has("name")){
			 filename=report.getJSONObject("target").getJSONObject("file").getString("name").replaceAll("\\s+", "");
			 
			 
		 }
		 //TODO
		
		 if(report.has("signatures")){
			 JSONArray signatures = report.getJSONArray("signatures");
			 for(int i=0;i<signatures.length();i++){
				 JSONObject signature = signatures.getJSONObject(i);
				 if(signature.has("marks")){
					 int severity=1;//how dangerous 
					 if(signature.has("severity")){
						 severity=signature.getInt("severity");
					 }
					 JSONArray marks = signature.getJSONArray("marks");
					 for(int j=0;j<marks.length();j++){
						 JSONObject mark = marks.getJSONObject(j);
						 if(mark.has("type") && mark.getString("type").compareTo("call")==0){//type is call
							 JSONObject call = mark.getJSONObject("call");
							 String feature="call";
							 if(call.has("category")){
								 feature=feature+"|"+call.getString("category");
							 }
							 if(call.has("api")){
								 feature=feature+"|"+call.getString("api");
							 }
							//TODO for more conditions
							 AddInCurrentFeature(feature,"");
							 
							 
						 }
						 else if(mark.has("type")){
							//TODO 
							 String feature = mark.getString("type");
							 if(mark.has("category")){
								 feature = feature+"|"+mark.getString("category");
							 }
							 AddInCurrentFeature(feature,"");
							 
						 }
						 else{
							 //TODO 
						 }
					 }
				 }
				 
			 }
		 }
		 
		 if(report.has("network")){
			 System.out.println("network");
			 
		 }
		 if(report.has("static")){
			 System.out.println("static");
		 }
		 if(report.has("dropped")){
			 System.out.println("dropped");
		 }
		 if(report.has("behavior")){
			 System.out.println("behavior");
			 //generic,apistats, processes, processestree, summary
			 if(report.getJSONObject("behavior").has("generic")){
				 
			 }
			 if(report.getJSONObject("behavior").has("apistats")){
				 
			 }
			 if(report.getJSONObject("behavior").has("processes")){
				 JSONArray processes = report.getJSONObject("behavior").getJSONArray("processes");
				 for(int p=0;p<processes.length();p++){
					 JSONObject process = processes.getJSONObject(p);
					 if(process.has("calls")){
						 JSONArray calls = process.getJSONArray("calls");
						 for(int c=0;c<calls.length();c++){
							 JSONObject call= calls.getJSONObject(c);
							 String feature="call";
							 if(call.has("category")){
								 feature=feature+"|"+call.getString("category").replaceAll("\\s+", "");
							 }
							 if(call.has("api")){
								 feature=feature+"|"+call.getString("api").replaceAll("\\s+", "");
							 }
							//TODO for more conditions
							 AddInCurrentFeature(feature,"");
						 }
					 }
					 if(process.has("modules")){
						 JSONArray modules = process.getJSONArray("modules");
						 for(int m=0;m<modules.length();m++){
							 String feature ="modules";
							 if(modules.getJSONObject(m).has("basename")){
								 if(filename.compareTo(modules.getJSONObject(m).getString("basename").replaceAll("\\s+", ""))!=0){
									 feature=feature+"|"+modules.getJSONObject(m).getString("basename").replaceAll("\\s+", "");
									 AddInCurrentFeature(feature,"");
								 }
								 
							 }
							 
						 }
						 
					 }
				 }
			 }
			 if(report.getJSONObject("behavior").has("summary")){
				 //connects_ip, file_created,file_recreated,regkey_written, dll_loaded, file_opened, 
				 //regkey_opened, command_line, file_written, regkey_deleted, file_deleted, file_exists,file_failed
				 //mutex,resolves_host, file_read, regkey_read
				 
			 }
		 }
		 if(report.has("info") && report.getJSONObject("info").has("score")){
			 System.out.println("score");
			 double score =report.getJSONObject("info").getDouble("score");
			 //System.out.println("score1");
			 AddInCurrentFeature("CuckooScore", score+"");
			 if(score>1.0){
				 AddInCurrentFeature("CuckooIsMalware", "yes");
				 //System.out.println("score2");
			 }
			 else{
				 AddInCurrentFeature("CuckooIsMalware", "no");
				 //System.out.println("score3");
			 }
			// System.out.println("score4");
		 }
		
		 if(report.has("virustotal")){
			 System.out.println("Virustotal");
			 //categorisation
			 HashMap<String,Integer> ResultType = new HashMap<>();
			 JSONObject virustotal = report.getJSONObject("virustotal");
			 if(virustotal.has("scans")){
				 JSONObject scans = virustotal.getJSONObject("scans");
				 for(String key:scans.keySet()){
					 
					 JSONObject scan = scans.getJSONObject(key);
					 if(scan.has("detected") && scan.getBoolean("detected")==true && scan.has("result")){
						 //System.out.println("true-"+key);
						 if(ResultType.get(scan.getString("result"))==null){
							 ResultType.put(scan.getString("result"), 1);
						 }
						 else{
							 ResultType.put(scan.getString("result"), ResultType.get(scan.getString("result"))+1);
						 }
					 }
					 else{
						 //System.out.println("false-"+key);
					 }
				 }
				  
				 
			 }
			 String ExistingType = ExistingMalwareType(ResultType);
			 System.out.println("Existing type:-"+ ExistingType);
			 AddInCurrentFeature("CuckooMalwareType",ExistingType);//Extracting Malware Type from Virustotal
			 
		 }
		 //if(Type_Train_Detect.compareToIgnoreCase("train")==0)
		 {
			 if(CurrentFeatures.get("CuckooIsMalware")!=null){
				 AddInCurrentFeature("ResultIsMalware", CurrentFeatures.get("CuckooIsMalware").type);
			 }
			 else{
				 AddInCurrentFeature("ResultIsMalware", "no");
				 AddInCurrentFeature("CuckooIsMalware", "no");
			 }
			 if(CurrentFeatures.get("CuckooMalwareType")!=null){
				 AddInCurrentFeature("ResultMalwareType", CurrentFeatures.get("CuckooMalwareType").type);
			 }
			 else{
				 AddInCurrentFeature("ResultMalwareType", "unknown");
				 AddInCurrentFeature("CuckooMalwareType", "unknown");
			 }
		 }
		 if(Type_Train_Detect.compareToIgnoreCase("train")==0){
			for(String f:MalwareTypes){
				if(filename.toLowerCase().contains(f.toLowerCase()) ){
					AddInCurrentFeature("ResultIsMalware", "yes");
					AddInCurrentFeature("ResultMalwareType", f);
				}
				else{
					AddInCurrentFeature("ResultIsMalware", "yes");
					AddInCurrentFeature("ResultMalwareType", "unknown");
				}
			}
		 }
		 else{
			 if(filename.toLowerCase().contains("clean")){
				 AddInCurrentFeature("ResultIsMalware", "no");
				 AddInCurrentFeature("ResultMalwareType", "unknown");
			 }
			 else if(filename.toLowerCase().contains("malware")){
				 AddInCurrentFeature("ResultIsMalware", "yes");
			 }
		 }
		 
		 
		 
		
	}
	public String ExistingMalwareType(HashMap<String, Integer> result) {
		UpdateResultType(result);//update different malware type as resulted from virustotal
		HashMap<String, Integer> MType = new HashMap<>();
		for(Map.Entry<String, Integer> entry : result.entrySet()){
			for(String type: MalwareTypes){
				if(entry.getKey().toLowerCase().contains(type)){
					if(MType.get(type)==null){
						MType.put(type, 1);
					}
					else{
						MType.put(type, MType.get(type)+1);
					}
				}
			}
		}
		String TypeOfMalware ="";
		for(Map.Entry<String, Integer> entry : MType.entrySet()){
			if(TypeOfMalware.compareTo("")==0){
				TypeOfMalware = entry.getKey();
			}
			else{
				if(MType.get(TypeOfMalware)<entry.getValue()){
					TypeOfMalware=entry.getKey();
				}
			}
		}
		if(TypeOfMalware.compareTo("")==0){
			return "unknown";
		}
		else{
			return TypeOfMalware;
		}
		
	}
	public  void UpdateResultType(HashMap<String, Integer> result){//update different malware type as resulted from virustotal
		HashMap<String , Integer> OldResult = new HashMap<>();
		int Id=0;
		try {
			BufferedReader br = new BufferedReader(new FileReader(MalwareTypeVirustotaltxt));
			try {
				String line = br.readLine();
				while(line!=null){
					if(line.length()>0){
						String a[] = line.split("\t");
						OldResult.put(a[1], Integer.parseInt(a[0]));
						Id=Integer.parseInt(a[0]);
					}
					line=br.readLine();
				}
				br.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(MalwareTypeVirustotaltxt,true));
			for(Map.Entry<String, Integer> entry:result.entrySet()){
				if(OldResult.get(entry.getKey())==null){
					Id++;
					bw.write(Id+"\t"+entry.getKey());
					bw.newLine();
				}
				
			}
			bw.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	public void AddInCurrentFeature(String feature,String type) {//type = count
		// TODO Auto-generated method stub
		if(CurrentFeatures.get(feature)==null){
			 FDetail p = new FDetail();
			 CurrentId++;
			 p.id = CurrentId;
			 p.count = 1;
			 if(type.compareTo("")==0){
				 p.type="countable";
			 }
			 else{
				 p.type=type;
			 }
			 CurrentFeatures.put(feature, p);
		 }
		 else{
			 FDetail p = CurrentFeatures.get(feature);
			 p.count++;
			 CurrentFeatures.put(feature, p);
		 }
	}
	public void SaveCurrentFeature(String name){
		try {
			String file= name+".txt";
			HashMap<Integer,String> sorted = SortById(CurrentFeatures);
			BufferedWriter bw = new BufferedWriter(new FileWriter(file));
			bw.write("FeatureId"+"\t"+"Feature"+"\t"+"FeatureType_Count");
			bw.newLine();
			for(Map.Entry<Integer, String> entry : sorted.entrySet()){
				bw.write(entry.getKey()+"\t"+entry.getValue());
				bw.newLine();
			}
			bw.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	public void UpdateAllFeatures(){
		int count=0;
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(AllFeaturesDBtxt,true));
			for(Map.Entry<String, FDetail> entry:CurrentFeatures.entrySet()){
				if(AllFeaturesDB.get(entry.getKey())==null){
					count++;
					int FeatureId=AllFeaturesDB.size()+1;
					AllFeaturesDB.put(entry.getKey(), FeatureId);
					bw.write(FeatureId+"\t"+entry.getKey());
					bw.newLine();
				}
			}
			bw.close();
			SortedAllFeaturesDB=SortById_AllFeature(AllFeaturesDB);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	
	}
	
	public void InitializeData(String type){
		String file ="";
		if(type.compareToIgnoreCase("train")==0){
			file=AllTrainDatatxt;
		}
		else{
			file=AllTestDatatxt;
		}
		System.out.println("Initializing Trainig data....");
		try {
			BufferedWriter bw=new BufferedWriter(new FileWriter(file));
			for(Map.Entry<Integer, String> entry:SortedAllFeaturesDB.entrySet()){
				//System.out.println(entry.getKey()+", "+entry.getValue());
				bw.write(entry.getValue()+"\t");
			}
			bw.newLine();
			bw.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void GenerateArffFormatMacro(){//format.arff to generate the structured format using allfeatures ismalware
		//
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(MacroFormatarff));
			bw.write("@relation MalwareDetection");
			bw.newLine();
			for(Map.Entry<Integer, String> entry : SortedAllFeaturesDB.entrySet()){
				if(entry.getValue().compareToIgnoreCase("CuckooMalwareType")==0 || entry.getValue().compareToIgnoreCase("ResultMalwareType")==0){
					//no need to add it
				}
				else if(entry.getValue().compareToIgnoreCase("CuckooIsMalware")==0 || entry.getValue().compareToIgnoreCase("ResultIsMalware")==0){
					bw.write("@attribute"+"\t"+entry.getValue()+"\t{yes, no}");
					bw.newLine();
				}
				else{
					bw.write("@attribute"+"\t"+entry.getValue()+"\tnumeric");
					bw.newLine();
				}
			}
			bw.write("@data");
			bw.newLine();
			bw.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void GenerateArffFormatMicro(){//format.arff to generate the structured format using allfeatures malwaretype
		//
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(MicroFormatarff));
			bw.write("@relation MalwareClassification");
			bw.newLine();
			for(Map.Entry<Integer, String> entry : SortedAllFeaturesDB.entrySet()){
				if(entry.getValue().compareToIgnoreCase("CuckooMalwareType")==0 || entry.getValue().compareToIgnoreCase("ResultMalwareType")==0){
					String line="@attribute"+"\t"+entry.getValue()+"\t{";
					for(int i=0;i<MalwareTypes.length-1;i++){
						line=line+MalwareTypes[i]+", ";
					}
					line=line+MalwareTypes[MalwareTypes.length-1]+"}";
					bw.write(line);
					bw.newLine();
				}
				else if(entry.getValue().compareToIgnoreCase("CuckooIsMalware")==0 || entry.getValue().compareToIgnoreCase("ResultIsMalware")==0){
					//no need
				}
				else{
					bw.write("@attribute"+"\t"+entry.getValue()+"\tnumeric");
					bw.newLine();
				}
			}
			bw.write("@data");
			bw.newLine();
			bw.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	//Generating Training and testing Data
	public void GenerateArffData(String type){
		if(type.compareToIgnoreCase("train")==0){
			GenerateArffDataMacro(MacroFormatarff,MalwareDetectionTrainDataSetsarff,AllTrainDatatxt);
			GenerateArffDataMicro(MicroFormatarff,MalwareClassificationTrainDataSetsarff,AllTrainDatatxt);
		}
		else{
			GenerateArffDataMacro(MacroFormatarff,MalwareDetectionTestDataSetsarff,AllTestDatatxt);
			GenerateArffDataMicro(MicroFormatarff,MalwareClassificationTestDataSetsarff,AllTestDatatxt);
		}
	}
	public void GenerateArffDataMacro(String formatfile,String file,String alldata){//generate the final arff format training data for detection
		System.out.println("Generating ArffData for Macro Classifier....");
		GenerateArffFormatMacro();
		try {
			BufferedWriter bw =new BufferedWriter(new FileWriter(file));
			
			BufferedReader br = new BufferedReader(new FileReader(formatfile));
			String line=br.readLine();
			while(line!=null){
				bw.write(line);
				bw.newLine();
				line = br.readLine();
			}
			br.close();
			br = new BufferedReader(new FileReader(alldata));
			line=br.readLine();
			line=br.readLine();
			while(line!=null){
				
				String str[] = line.split("\t");
				line="";
				for(int i=0;i<str.length;i++){
					if(i==2 || i==4){}//for malwaretype}
					else{
						line=line+str[i]+"\t";
					}
					
				}
				bw.write(line);
				bw.newLine();
				line=br.readLine();
			}
			
			br.close();
			bw.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	public void GenerateArffDataMicro(String formatfile,String file,String alldata){//generate the final arff format training data for classification
		System.out.println("Generating ArffData for Micro Classifier....");
		GenerateArffFormatMicro();
		try {
			BufferedWriter bw =new BufferedWriter(new FileWriter(file));
			
			BufferedReader br = new BufferedReader(new FileReader(formatfile));
			String line=br.readLine();
			while(line!=null){
				bw.write(line);
				bw.newLine();
				line = br.readLine();
			}
			br.close();
			br = new BufferedReader(new FileReader(alldata));
			line=br.readLine();
			line=br.readLine();
			while(line!=null){
				
				String str[] = line.split("\t");
				line="";
				for(int i=0;i<str.length;i++){
					if(i==1 || i==3){}//for ismalware
					else{
						line=line+str[i]+"\t";
					}
					
				}
				bw.write(line);
				bw.newLine();
				line=br.readLine();
			}
			
			br.close();
			bw.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	
	
	//add one instance
	public void AddAnInstanceOfData(String type){
		if(type.compareToIgnoreCase("train")==0){
			//SortedAllFeaturesDB=SortById_AllFeature(AllFeaturesDB);
			AddInstanceToData(AllTrainDatatxt);
			AddInstanceArffDataMacro(MalwareDetectionTrainDataSetsarff);
			if(CurrentFeatures.get("ResultIsMalware")!=null && CurrentFeatures.get("ResultIsMalware").type.compareToIgnoreCase("yes")==0)
			AddInstanceArffDataMicro(MalwareClassificationTrainDataSetsarff);
		}
		else{
			//SortedAllFeaturesDB=SortById_AllFeature(AllFeaturesDB);
			AddInstanceToData(AllTestDatatxt);
			AddInstanceArffDataMacro(MalwareDetectionTestDataSetsarff);
			if(CurrentFeatures.get("ResultIsMalware")!=null && CurrentFeatures.get("ResultIsMalware").type.compareToIgnoreCase("yes")==0)
			AddInstanceArffDataMicro(MalwareClassificationTestDataSetsarff);
		}
	}
	public void AddInstanceArffDataMacro(String filename){
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(filename,true));
			String line="";
			for(Map.Entry<Integer, String> entry:SortedAllFeaturesDB.entrySet()){
				//System.out.println(entry.getKey()+", "+entry.getValue());
				if(CurrentFeatures.get(entry.getValue())==null){
					line=line+"0.0"+"\t";
				}
				else{
					if(entry.getValue().compareToIgnoreCase("CuckooMalwareType")==0 || entry.getValue().compareToIgnoreCase("ResultMalwareType")==0){
						//no need to add it
					}
					else if(CurrentFeatures.get(entry.getValue()).type.compareToIgnoreCase("countable")==0){
						line=line+CurrentFeatures.get(entry.getValue()).count+"\t";
					}
					else {
						line=line+CurrentFeatures.get(entry.getValue()).type+"\t";
					}
				}
			}
			bw.write(line);
			bw.newLine();
			bw.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void AddInstanceArffDataMicro(String filename){
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(filename,true));
			String line="";
			for(Map.Entry<Integer, String> entry:SortedAllFeaturesDB.entrySet()){
				//System.out.println(entry.getKey()+", "+entry.getValue());
				if(CurrentFeatures.get(entry.getValue())==null){
					line=line+"0.0"+"\t";
				}
				else{
					if(entry.getValue().compareToIgnoreCase("CuckooIsMalware")==0 || entry.getValue().compareToIgnoreCase("ResultIsMalware")==0){
						//no need
					}
					else if(CurrentFeatures.get(entry.getValue()).type.compareToIgnoreCase("countable")==0){
						line=line+CurrentFeatures.get(entry.getValue()).count+"\t";
					}
					else{
						line=line+CurrentFeatures.get(entry.getValue()).type+"\t";
					}
				}
			}
			bw.write(line);
			bw.newLine();
			bw.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void AddInstanceToData(String filename){//add one instance in alldata.txt
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(filename,true));
			String line="";
			for(Map.Entry<Integer, String> entry:SortedAllFeaturesDB.entrySet()){
				//System.out.println(entry.getKey()+", "+entry.getValue());
				if(CurrentFeatures.get(entry.getValue())==null){
					line=line+"0.0"+"\t";
				}
				else{
					if(CurrentFeatures.get(entry.getValue()).type.compareToIgnoreCase("countable")==0){
						line=line+CurrentFeatures.get(entry.getValue()).count+"\t";
					}
					else{
						line=line+CurrentFeatures.get(entry.getValue()).type+"\t";
					}
				}
			}
			bw.write(line);
			bw.newLine();
			bw.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	
	public JSONObject parseJSONFile(String filename) throws JSONException, IOException {
        String content = new String(Files.readAllBytes(Paths.get(filename)));
        return new JSONObject(content);
    }
	public HashMap<Integer, String> SortById(HashMap<String, FDetail> map){
		HashMap<Integer,String> sorted= new HashMap<>();
		for(Map.Entry<String, FDetail> entry:map.entrySet()){
			if(entry.getValue().type.compareToIgnoreCase("countable")==0){
				sorted.put(entry.getValue().id, ""+entry.getKey()+"\t" +entry.getValue().count);
			}
			else{
				sorted.put(entry.getValue().id, ""+entry.getKey()+"\t" +entry.getValue().type);
			}
		}
		return sorted;
		
	}
	public TreeMap<Integer, String> SortById_AllFeature(HashMap<String,Integer> map){
		TreeMap<Integer, String> sorted = new TreeMap<>();
		for(Map.Entry<String,Integer> entry:map.entrySet()){
			sorted.put(entry.getValue(), entry.getKey());
		}
		return sorted;
	}
}
class FDetail{//Fdetail
	int id;
	double count;
	String type;//countable and type
}
