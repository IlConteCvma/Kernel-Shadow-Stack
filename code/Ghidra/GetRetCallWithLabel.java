
//@author Marco Calavaro
//@category code_analysis
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.task.*;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Stack;
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.nio.file.*;
import java.io.*;
import ghidra.program.model.block.CodeBlockModel;
import java.lang.System;

public class GetRetCallWithLabel extends GhidraScript {

    // TODO
    String path_base = "/path/kss-test/";

    int num_call_in = 0;

    /* List for all RET addresses */
    ArrayList<ArrayList<Long>> ret_addr_funcs = new ArrayList<>();
    /* List for all CALL addresses */
    ArrayList<ArrayList<Long>> call_reference_addresses = new ArrayList<>();

    ArrayList<Boolean> func_is_in_list = new ArrayList<>();
    ArrayList<Function> final_good_funcs = new ArrayList<>();
    ArrayList<ArrayList<Long>> final_call_reference_addresses = new ArrayList<>();

    private long addr_value_start = 0;
    private long addr_value_end = 0;

    //
    public int save_instruction_on_file(ArrayList<Function> good_funcs, int count_is_in) {
        String app_name;
        String filename_call;
        String filename_ret;
        String path_program_dir;
        String call_tag = "call_";
        String ret_tag = "ret_";
        String call_subdir = "/call";
        String ret_subdir = "/ret";
        String sep = "_";
        String format = ".txt";
        String num_call_file = "number";
        ArrayList<Long> addr_already_write;
        boolean ret;
        String path;
        PrintWriter writer = null;

        /* Retrive app name */
        app_name = currentProgram.getName();
        printf("Program in analysis '%s'\n", app_name);

        filename_call = call_tag + app_name + format;
        filename_ret = ret_tag + app_name + format;

        path_program_dir = path_base + app_name + sep;

        printf("The directory for the program '%s' is '%s'\n", app_name, path_program_dir);

        // Create the directory for analysis output

        if (!createDirectoryByPath(path_program_dir)) {
            return -1;
        }

        if (this.addr_value_start <= 0 && this.addr_value_end <= 0 && this.addr_value_start == this.addr_value_end) {
            printf("ERROR for instrumentation zone values\n");
            return -1;
        }

        // Create file for the zone
        path = path_program_dir + "/zone.txt";
        if (!createFileByName(path)) {
            return -1;
        }
        // Writing on the file
        try {
            writeALineOnAFile(path,Long.toHexString(this.addr_value_start));
			writeALineOnAFile(path,Long.toHexString(this.addr_value_end));
		} catch (Exception e) {
			printf("ERROR on writing the zone to the file %s\n",path);
			return -1;
		}

        // --------------------------------

        // Create file for the number of good function without IN scenarios
        path = path_program_dir + "/num_good_func_no_is_in.txt";
        if (!createFileByName(path)) {
            return -1;
        }
        // Writing on the file
        try {
            writeALineOnAFile(path,Integer.toString(good_funcs.size() - count_is_in));
		} catch (Exception e) {
			printf("ERROR on writing on the file %s\n",path);
			return -1;
		}

        // --------------------------------

        // Create file for the number of good function
        path = path_program_dir + "/num_good_func.txt";
        if (!createFileByName(path)) {
            return -1;
        }
        // Writing on the file
        try {
            writeALineOnAFile(path,Integer.toString(good_funcs.size()));
		} catch (Exception e) {
			printf("ERROR on writing on the file %s\n",path);
			return -1;
		}


        // Create dir for CALL informations
        if (!createDirectoryByPath(path_program_dir + call_subdir)) {
            return -1;
        }
        // Create dir for RET informations
        if (!createDirectoryByPath(path_program_dir + ret_subdir)) {
            return -1;
        }

        // Create the information files

        path = path_program_dir + call_subdir + "/" + filename_call ;
        if (!createFileByName(path)) {
            return -1;
        }

        path = path_program_dir + call_subdir + "/" + num_call_file + format ;
        if (!createFileByName(path)) {
            return -1;
        }

        path = path_program_dir + ret_subdir + "/" + filename_ret ;
        if (!createFileByName(path)) {
            return -1;
        }

        // Writing on CALL file the offset discovered
        int total_call = 0;
        path = path_program_dir + call_subdir + "/" + filename_call ;
        writer = givePrintWriterForAFile(path);
        if (writer == null){
            printf("ERROR On writer creation\n");
			return -1;
        }

        addr_already_write = new ArrayList<Long>();
        for(int i=0; i < good_funcs.size(); i++) {

			/* Retrive CALL list for the actual function */
			ArrayList<Long> call_addresses = this.final_call_reference_addresses.get(i);

			try {
				for(int idx = 0; idx < call_addresses.size(); idx++) {
					if(addr_already_write.contains(call_addresses.get(idx))) {
						continue;
					}
					addr_already_write.add(call_addresses.get(idx));
					writer.print(Long.toHexString(call_addresses.get(idx)));
					writer.print(",");
					if(func_is_in_list.get(i) == true) {
						writer.print(Integer.toString(1));
					} else {
						writer.print(Integer.toString(0));
					}
					writer.print(",");
					writer.print(Integer.toString(i));
					writer.print(",");
					String tmp = good_funcs.get(i).getName();
					if (tmp.length() > 50){
						writer.println(tmp.substring(0,50));
					}else{
						writer.println(tmp);
					}
					total_call = total_call + 1;
				}
				writer.flush();
				
			} catch (Exception e) {
				printf("ERROR On write Call offset file\n");
                return -1;
			}
		}

        writer.close();

        path = path_program_dir + call_subdir + "/" + num_call_file + format;
        try {
            writeALineOnAFile(path,Long.toString(total_call));
		} catch (Exception e) {
			printf("ERROR on writing on the file %s\n",path);
			return -1;
		}


        // Writing on RET file the offset discovered
        int total_ret = 0;

		path = path_program_dir + ret_subdir + "/" + filename_ret;
        writer = givePrintWriterForAFile(path);
        if (writer == null){
            printf("ERROR On writer creation\n");
			return -1;
        }
        addr_already_write = new ArrayList<Long>();
        for(int i=0; i < good_funcs.size(); i++) {

			/* Recupero la lista delle RET per la funzione corrente */
			ArrayList<Long> ret_addresses = ret_addr_funcs.get(i);

			try {
				for(int idx = 0; idx < ret_addresses.size(); idx++) {
					if(addr_already_write.contains(ret_addresses.get(idx))) {
						continue;
					}
					addr_already_write.add(ret_addresses.get(idx));
					writer.print(Long.toHexString(ret_addresses.get(idx)));
					writer.print(",");
					if(func_is_in_list.get(i) == true) {
						writer.print(Integer.toHexString(1));
					} else {
						writer.print(Integer.toHexString(0));
					}
					writer.print(",");
					writer.print(Integer.toString(i));
					writer.print(",");
					String tmp = good_funcs.get(i).getName();
					if (tmp.length() > 50){
						writer.println(tmp.substring(0,50));
					}else{
						writer.println(tmp);
					}
					total_ret = total_ret + 1;
				}
				writer.flush();
				
			} catch (Exception e) {
				printf("Errore nella scrittura su File degli offset di RET");
			}
		}

		writer.close();

        path = path_program_dir + ret_subdir + "/" + num_call_file + format;

        try {
            writeALineOnAFile(path,Long.toString(total_ret));
		} catch (Exception e) {
			printf("ERROR on writing on the file %s\n",path);
			return -1;
		}

        return 0;
    }

    public PrintWriter givePrintWriterForAFile(String file){
        try {
			return new PrintWriter(new BufferedWriter(new FileWriter(file)));
		}catch (Exception e) {
			return null;
		}
    }

    public Exception writeALineOnAFile(String file,String line)}{
        try {
			PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(file)));
			writer.println(line);
			writer.flush();
			writer.close();
		} catch (Exception e) {
			throw e;
		}
    }

    public boolean createDirectoryByPath(String path) {
        Path newDirPath = Paths.get(path);
        if (Files.exists(newDirPath) && Files.isDirectory(newDirPath)) {
            printf("The directory exist, cannot crete a new one\n");
            return false;
        }
        try {
            Files.createDirectories(newDirPath);
        } catch (Exception e) {
            printf("Error on creation of the directory\n");
            return false;
        }
        return true;
    }

    public boolean createFileByName(String fileName) {
        File newFile = new File(fileName);

        try {
            if (!newFile.createNewFile()) {
                printf("Error on create new file\n");
                return false;
            }
        } catch (Exception e) {
            printf("Errore nella creazione del file contenente gli estremi delle zone di instrumentazione\n");
            return false;
        }
        return true;
    }

}