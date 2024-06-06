

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

    int num_call_in = 0;
	//TODO
    public static String path_base = "/home/marco/kss-test";
    /* L'i-esimo elemento delle tre liste successive contiene le informazioni relative ad una stessa funzione */

    /* Lista contenente gli indirizzi di tutte le RET per ogni funzione di interesse */
    ArrayList<ArrayList<Long>> ret_addr_funcs = new ArrayList<>();

    /* Lista di liste degli indirizzi delle CALL verso le funzioni 		     */
    ArrayList <ArrayList<Long>> call_reference_addresses = new ArrayList<>();

    /* Mi dice se l'instrumentazione della corrispondente funzione può portare a scenari IN */
    ArrayList <Boolean> func_is_in_list = new ArrayList<>();

    ArrayList<Function> final_good_funcs = new ArrayList<>();

    ArrayList <ArrayList<Long>> final_call_reference_addresses = new ArrayList<>();




    /**
     * save_instruction_on_file - Memorizza gli offset delle RET/CALL, il numero delle RET/CALL, l'intervallo della zona
     * .text che è stata instrumentata, il numero delle funzioni buone e il numero delle funzioni buone ma che non generano
     * scenari di tipo IN all'interno di specifici file.
     *
     * @addr_value_start: Inizio della sezione .text
     * @addr_value_end  : Fine della sezione .text
     * @good_funcs	: Lista delle 'buone' funzioni
     * @count_is_in	: Numero di 'buone' funzioni che possono generare degli scenari di tipo IN
     *
     * @return: Restituisce il valore 0 se le scritture sono state eseguite correttamente; altrimenti, restituisce il valore -1.
     */ 
    public int save_instruction_on_file(long addr_value_start, long addr_value_end, ArrayList<Function> good_funcs, int count_is_in) {
		String app_name;
		String filename_call;
		String filename_ret;
		String path_program_dir;
		static String call_tag = "call_";
		static String ret_tag = "ret_";
		static String call_subdir = "/call";
		static String ret_subdir = "/ret";
		static String sep = "_";
		static String format = ".txt";
		static String num_call_file = "number";
		ArrayList<Long> addr_already_write;
	

		/* Cartella di lavoro dove è presente il modulo kernel */
		

		/* Recupero il nome del programma che sto analizzando */
		app_name = currentProgram.getName();

		printf("E' stato analizzato il programma '%s'\n", app_name);

		/* Definisco il nome del file contenente gli offset relativi alle CALL */
		filename_call = call_tag + app_name + format;

		/* Definisco il nome del file contenente gli offset relativi alle RET  */
		filename_ret = ret_tag + app_name + format;

		printf("Il nome del file che conterrà le CALL è: %s\n", filename_call);

		printf("Il nome del file che conterrà le CALL è: %s\n", filename_ret);

		path_program_dir = path_base + app_name + sep;

		printf("La nuova cartella associata al programma '%s' è '%s'\n", app_name, path_program_dir);

		/* Creo le tre cartelle	*/

		/* Creo la cartella che contiene le informazioni di instrumentazione per il programma */
		Path newDirPath = Paths.get(path_program_dir);

		if(Files.exists(newDirPath) && Files.isDirectory(newDirPath)) {
			printf("La cartella è già stata creata. Impossibile sovrascrivere la cartella\n");
			return 1;
		}

		try {
			Files.createDirectories(newDirPath);
		} catch (Exception e) {
			printf("Errore nella creazione della directory per il programma\n");
			return 1;
		}

    		/* Creo il file contenente gli estremi della zona di memoria instrumentata */

    		if(addr_value_start <= 0 && addr_value_end <= 0 && addr_value_start == addr_value_end) {
        		printf("Errore nel determinare la zona di instrumentazione... estremi non validi\n");
        		return -1;
    		}

		File newFile = new File(path_program_dir + "/zone.txt");

		try {
			if(!newFile.createNewFile()) {
				printf("Il file con gli estremi delle zone di instrumentazione esiste già oppure si è verificato un errore\n");
				return -1;
			}
		} catch (Exception e) {
			printf("Errore nella creazione del file contenente gli estremi delle zone di instrumentazione\n");
			return -1;
		}

    		/* Scrivo gli indirizzi iniziale e finale della zona di instrumentazione */
    		try {
			String path = path_program_dir + "/zone.txt";
			PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(path)));
			writer.println(Long.toHexString(addr_value_start));
        		writer.println(Long.toHexString(addr_value_end));
			writer.flush();
			writer.close();
		} catch (Exception e) {
			printf("Errore nella scrittura su File contenente gli estremi delle zone di instrumentazione\n");
			return -1;
		}

		/* Creo i due file che contengono il numero delle funzioni buone e il numero delle funzioni buone senza scenari IN */
		newFile = new File(path_program_dir + "/num_good_func_no_is_in.txt");

		try {
			if(!newFile.createNewFile()) {
				printf("Il file contenente il numero delle funzioni buone senza scenari IN esiste già oppure si è verificato un errore\n");
				return -1;
			}
		} catch (Exception e) {
			printf("Errore nella creazione del file contenente il numero delle funzioni buone senza scenari IN\n");
			return -1;
		}

    		/* Scrivo il numero delle funzioni */
    		try {
			String path = path_program_dir + "/num_good_func_no_is_in.txt";
			PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(path)));
			writer.println(Integer.toString(good_funcs.size() - count_is_in));
			writer.flush();
			writer.close();
		} catch (Exception e) {
			printf("Errore nella scrittura su File contenente contenente il numero delle funzioni buone senza scenari IN \n");
			return -1;
		}

		newFile = new File(path_program_dir + "/num_good_func.txt");

		try {
			if(!newFile.createNewFile()) {
				printf("Il file contenente il numero delle funzioni buone esiste già oppure si è verificato un errore\n");
				return -1;
			}
		} catch (Exception e) {
			printf("Errore nella creazione del file contenente il numero delle funzioni buone\n");
			return -1;
		}

    		/* Scrivo il numero delle funzioni */
    		try {
			String path = path_program_dir + "/num_good_func.txt";
			PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(path)));
			writer.println(Integer.toString(good_funcs.size()));
			writer.flush();
			writer.close();
		} catch (Exception e) {
			printf("Errore nella scrittura su File contenente contenente il numero delle funzioni buone\n");
			return -1;
		}

		/* Creo la cartella che contiene le informazioni di CALL per il programma */
		newDirPath = Paths.get(path_program_dir + call_subdir);

		try {
			Files.createDirectories(newDirPath);
		} catch (Exception e) {
			printf("Errore nella creazione della directory per le CALL\n");
			return -1;
		}

		/* Creo la cartella che contiene le informazioni di RET per il programma */
		newDirPath = Paths.get(path_program_dir + ret_subdir);

		try {
			Files.createDirectories(newDirPath);
		} catch (Exception e) {
			printf("Errore nella creazione della directory per le RET\n");
			return -1;
		}

		/* Creazione del file contenente gli offset delle CALL */
		newFile = new File(path_program_dir + call_subdir + "/" + filename_call);

		try {
			if(!newFile.createNewFile()) {
				printf("Il file con gli offset delle CALL esiste già oppure si è verificato un errore\n");
				return -1;
			}
		} catch (Exception e) {
			printf("Errore nella creazione del file contenente gli offset delle CALL\n");
			return -1;
		}

		/* Creazione del file contenente il numero delle CALL */
		newFile = new File(path_program_dir + call_subdir + "/" + num_call_file + format);

		try {
			if(!newFile.createNewFile()) {
				printf("Il file con il numero di CALL esiste già oppure si è verificato un errore\n");
				return -1;
			}
		} catch (Exception e) {
			printf("Errore nella creazione del file contenente il numero delle CALL\n");
			return -1;
		}

		/* Creazione del file contenente gli offset delle RET */
		newFile = new File(path_program_dir + ret_subdir + "/" + filename_ret);

		try {
			if(!newFile.createNewFile()) {
				printf("Il file con gli offset delle RET esiste già oppure si è verificato un errore\n");
				return -1;
			}
		} catch (Exception e) {
			printf("Errore nella creazione del file contenente gli offset delle RET\n");
			return -1;
		}

		PrintWriter writer = null;

		/* Scrittura degli offset di CALL */

		int total_call = 0;

		String path = path_program_dir + call_subdir + "/" + filename_call;

		try {
			writer = new PrintWriter(new BufferedWriter(new FileWriter(path)));
		}catch (Exception e) {
			printf("ERRORE creazione writer\n");
			return -1;
		}

		addr_already_write = new ArrayList<Long>();

		for(int i=0; i < good_funcs.size(); i++) {

			/* Recupero la lista delle CALL per la funzione corrente */
			ArrayList<Long> call_addresses = final_call_reference_addresses.get(i);

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
					writer.println(good_funcs.get(i).getName());
					total_call = total_call + 1;
				}
				writer.flush();
				
			} catch (Exception e) {
				printf("Errore nella scrittura su File degli offset di CALL");
			}
		}

		writer.close();


		try {
			path = path_program_dir + call_subdir + "/" + num_call_file + format;
			writer = new PrintWriter(new BufferedWriter(new FileWriter(path)));
			writer.println(Long.toString(total_call));
			writer.flush();
			writer.close();
		} catch (Exception e) {
			printf("Errore nella scrittura su File del numero di CALL");
		}

		/* Scrittura degli offset di RET */
		int total_ret = 0;

		path = path_program_dir + ret_subdir + "/" + filename_ret;

		try {
			writer = new PrintWriter(new BufferedWriter(new FileWriter(path)));
		}catch (Exception e) {
			printf("ERRORE creazione writer\n");
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
					writer.println(good_funcs.get(i).getName());
					total_ret = total_ret + 1;
				}
				writer.flush();
				
			} catch (Exception e) {
				printf("Errore nella scrittura su File degli offset di RET");
			}
		}

		writer.close();

		try {
			path = path_program_dir + ret_subdir + "/" + num_call_file + format;
			writer = new PrintWriter(new BufferedWriter(new FileWriter(path)));
			writer.println(Long.toString(total_ret));
			writer.flush();
			writer.close();
		} catch (Exception e) {
			printf("Errore nella scrittura su File del numero di RET");
		}

		return 0;
    }


    /**
     * getCodeBlockArray - Recupera tutti i blocchi di codice che appaiono nel FG della funzione.
     *
     * @func: Funzione di cui si vuole recuperare i blocchi del FG
     *
     * @return: Restituisce la lista dei blocchi di codice del FG.
     */
    public ArrayList<CodeBlock> getCodeBlockArray(Function func) {
		ArrayList<CodeBlock> codeBlockArray;

		CodeBlockModel codeBlockModel = new BasicBlockModel(currentProgram);
		codeBlockArray = new ArrayList<CodeBlock>();

		try{
			CodeBlockIterator codeBlockIterator = codeBlockModel.getCodeBlocksContaining(func.getBody(), monitor);

			while(codeBlockIterator.hasNext()) {
				CodeBlock codeBlock = codeBlockIterator.next();
				codeBlockArray.add(codeBlock);
			}

		}catch(Exception e) {
			printf("[ERRORE NEL RECUPERO DEI BLOCCHI NEL FG] Non è possibile recuperare i blocchi di codice della funzion %s:\n%s\n", func.getName(), e.getMessage());
		}

		return codeBlockArray;
    }

    /**
     * DFS_iterative - Implementa una visita in profondità dei blocchi appartenenti al grafo che ha come nodo
     * radice il blocco @root. L'obiettivo è trovare tutte le RET che potrebbero essere eseguite dalla funzione
     * e verificare se ci potrebbe essere la possibilità di avere scenari di tipo IN.
     *
     * @root			    : Blocco di codice radice
     * @return_instruction_addr_list: Lista degli offset delle istruzioni di RET eseguibili dalla funzione
     * @base			    : Base scelta da Ghidra
     * @codeBlockModel		    : Modello di blocco di codice
     * @func			    : Funzione sotto analisi
     * @start_text		    : Inizio della sezione .text
     * @end_text		    : Fine della sezione .text
     * @good_funcs		    : Lista delle funzioni che rispettano i primi criteri di filtraggio
     *
     * @return: Restituisce il valore 1 se bisogna etichettare le istruzioni di CALL e di ret; Il valore 0 se
     * tutti i cammini del grafo terminano correttamente; altrimenti, restituisce il valore -1 in caso di errore. 
     */
    public int DFS_iterative(CodeBlock root, ArrayList<Long> return_instruction_addr_list, long base, CodeBlockModel codeBlockModel, Function func, long start_text, long end_text, ArrayList<Function> good_funcs) {

		int is_in;
		Stack<CodeBlock> stack;
		ArrayList<CodeBlock> blocks_checked;
		CodeBlockReferenceIterator iter = null;
		boolean ret_instr;
		int num_jumps;
		int num_calls;
		Instruction instruction = null;
		FlowType flowType;
		CodeBlock neighbor_block = null;

		Listing plist = currentProgram.getListing();

		/* Assumo che i cammini del grafo che hanno come radice 'root' contengano dei blocchi che non portano a scenari di tipo IN */
		is_in = 0;
	
		/* Istanzio lo stack che verrà utilizzato per implementare la visita in profondità del grafo	   */
		stack = new Stack<CodeBlock>();

		/* Istanzio una lista per rilevare eventuali loop all'interno del grafo */
		blocks_checked = new ArrayList<CodeBlock>();

		/* Il primo nodo che deve essere visitato è la radice del grafo */
		stack.push(root);

		if(func.getName().equals("FUN_00146400")) {
			printf("Visita in profondità per la funzione %s. Il grafo ha come blocco radice [%x, %x]\n", func.getName(), root.getMinAddress().getOffset(), root.getMaxAddress().getOffset());
		}

		/*
		 * Eseguo la visita in profondità del grafo avente come nodo radice il blocco di codice 'root'.Man
		 * mano che i nodi vengono visitati, i vicini sono inseriti all'interno dello stack. Si itera fino
		 * a quando esiste un blocco che NON E' STATO ANCORA MAI VISITATO. La seconda condizione consente
		 * di terminare l'esecuzione dello script Ghidra se ci dovesse impiegare troppo tempo.
		 */

		while(!(stack.empty()) && !monitor.isCancelled()) {

			/* Recupero il prossimo blocco di codice da visitare */
			CodeBlock codeBlock = stack.pop();

			/*
			 * Verifico se il blocco corrente è stato già visitato. Questo può accadere sia nel
			 * caso in cui abbiamo un grafo con cicli sia se il blocco ha molteplici frecce che
			 * entrano. In entrambi i casi, il blocco deve essere visitato una volta sola sennò
			 * si rischierebbe di entrare in un ciclo senza fine. Se il blocco è presente nella
			 * lista 'blocks_checked' allora è stato già visitato precedentemente.
			 */

			if(blocks_checked.contains(codeBlock)) {
				//printf("[CICLO] Il blocco [%x, %x] nel grafo esterno con radice [%x, %x] viene analizzato più volte\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), root.getMinAddress().getOffset(), root.getMaxAddress().getOffset());
				continue;
			}

			/* Inserisco il blocco corrente nella lista dei blocchi che sono stati visitato */
			blocks_checked.add(codeBlock);

			if(func.getName().equals("FUN_00146400")) {
				printf("Inizio l'analisi del blocco [%x, %x] all'interno del grafo...\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
			}

			try {

				/* Costruisco l'iteratore sui blocchi che sono nel grafo i vicini del blocco corrente */
				iter = codeBlock.getDestinations(monitor);

			} catch(Exception e) {

				printf("[ERRORE RECUPERO DESTINAZIONI] Errore nel recupero di TUTTI i vicini del blocco [%x, %x]:\n%s\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), e.getMessage());
				return -1;
			}

			/*
			 * Per ogni blocco che tiro fuori dallo stack devo:
			 * 1. Trovare tutti i vicini che dovranno essere visitati
			 * 2. Trovare tutte le istruzioni di RET
			 * 3. Verificare se esistono possibili scenari IN
			 * 4. Trovare eventuali salti che Ghidra non sa risolvere
			 */

			try {

				/*
				 * Itero su tutti i blocchi ch sono i vicini del blocco corrente nel grado esterno per inserirli
				 * all'interno dello stack in modo da poterli visitare successivamente.
				 */

				while(iter.hasNext()) {

					/* Recupero il riferimento al prossimo blocco di codice	vicino */
					CodeBlockReference cbr = iter.next();

					/* Recupero il blocco di codice che nel grafo è il vicino del blocco corrente	*/				
					neighbor_block = cbr.getDestinationBlock();

					/* Recupero l'indirizzo dell'istruzione macchina nel blocco corrente che passa il controllo al blocco vicino */
					Address referent_addr = cbr.getReferent();

					/* Recupero l'istruzione macchina nel blocco corrente che passa il controllo al blocco vicino */
					Instruction referent_instr = plist.getInstructionAt(referent_addr);

					if(referent_instr == null) {
						printf("[ERRORE RECUPERO ISTRUZIONE SORGENTE] Errore nel determinare l'istruzione che salta al blocco vicino\n");
						return -1;
					}

					/*
					 * Cerco di capire la tipologia di riferimento. Infatti, il metodo getDestinations() considera anche
					 * le destinazioni (i.e., le frecce uscenti dal blocco corrente) che sono associate ad una istruzione
					 * di CALL. Una istruzione di CALL salta ad un'altra funzione che non è detto io debba instrumentare.
					 * Bisogna inserire nello stack solamente quei blocchi che sono raggiunti tramite una istruzione
					 * sorgente che è un salto oppure una istruzione che termina il blocco corrente. Quest'ultimo caso
					 * rappresenta il normale passaggio da una istruzione alla sua successiva.
					 */

					/* Recupero la modalità con cui si passa al blocco di destinazione	*/
					flowType = referent_instr.getFlowType();

					if((flowType.isJump() || flowType.isCall()) && referent_instr.getMnemonicString().startsWith("J")) {

						/* L'istruzione che passa il controllo al blocco vicino è una tipologia di salto (e.g., JMP, JZ)


						/*
						 * Verifico se il nodo vicino cade all'interno della sezione .text o se è esterno. Se fosse
						 * un blocco esterno allora sarebbe necessario etichettare le itsruzioni poiché l'instrumentazione
						 * avviene solamente per le funzioni nella sezione .text. Probabilmente, con questo salto si passa
						 * alla 'plt' per invocare funzioni di librerie esterne.
						 */

						if((neighbor_block.getMinAddress().getOffset() - base) < start_text || (neighbor_block.getMaxAddress().getOffset() - base) > end_text) {

							/* Con questa JUMP passiamo ad eseguire in una zona di codice in cui non ricerco le istruzioni di RET */
							is_in = 1;
							if(func.getName().equals("FUN_00146400")) {
								printf("Fuori sezione .text\n");
							}

						} else {

							/* 
							 * Inserisco il blocco di codice nello stack solamente se non è già presente e se non fa parte
							 * di una funzione che considero buona. Infatti, non dovrei instrumentare una RET che appartiene
							 * ad un'altra funzione. E' possibile che si passi ad eseguire una nuova buona funzione tramite
							 * una JUMP.
							 */

							/* Recupero la funzione a cui appartiene questo blocco di codice target */
							Function func_target = getFunctionContaining(neighbor_block.getFirstStartAddress());
					
							if(good_funcs.contains(func_target) && func_target != func) {
								is_in = 1;
							} else {
								if(stack.search(neighbor_block) == -1) {
									stack.push(neighbor_block);
								}
							}
						}

					} else if((flowType.isJump() || flowType.isCall()) && referent_instr.getMnemonicString().contains("CALL")) {

						/*
						 * Se l'istruzione di CALL che consente il passaggio al corrente blocco di codice target NON è l'ultima
						 * istruzione macchina del blocco di codice corrente allora sono sicuro che questo blocco NON lo dovrò
						 * considerare nella visita in profondità del grafo perché mi porterà verso una funzione DIFFERENTE. Tuttavia,
						 * se l'istruzione di CALL è l'ultima del blocco di codice corrente allora avrà associate due frecce uscenti:
						 * una freccia verso il blocco di codice della funzione chiamata e un'altra verso il blocco di codice che
						 * contiene l'istruzione macchina successiva a seconda della logica applicativa. Nell'ultimo caso bisogna
						 * considerare tale blocco nella visita in profondità del grafo.
						 */

						/* Verifico se l'istruzione di CALL con cui passo al blocco target è l'ultima istruzione del blocco di codice corrente */

						if((referent_instr.getAddress().getOffset() + referent_instr.getLength() - 1) == codeBlock.getMaxAddress().getOffset()) {

							if(func.getName().equals("FUN_00146400")) {
								printf("Nel blocco [%x, %x] una CALL è l'ultima istruzione macchina\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
							}

							/* Verifico se il blocco target corrente contiene l'istruzione macchina successiva all'ultima del blocco di codice corrente */
							if(neighbor_block.getMinAddress().getOffset() == (codeBlock.getMaxAddress().getOffset() + 1)) {

								if((neighbor_block.getMinAddress().getOffset() - base) < start_text || (neighbor_block.getMaxAddress().getOffset() - base) > end_text) {
									if(func.getName().equals("FUN_00146400")) {
										printf("Fuori sezione .text\n");
									}
									/* Con questa JUMP passiamo ad eseguire in una zona di codice in cui non ricerco le istruzioni di RET */
									is_in = 1;

								} else {

									/* Recupero la funzione a cui appartiene questo blocco di codice target */
									Function func_target = getFunctionContaining(neighbor_block.getFirstStartAddress());
					
									if(good_funcs.contains(func_target) && func_target != func) {
										is_in = 1;
									} else {
										if(func.getName().equals("FUN_00146400")) {
											printf("Il blocco vicino [%x, %x] è il successivo del blocco corrente [%x, %x]\n", neighbor_block.getMinAddress().getOffset(), neighbor_block.getMaxAddress().getOffset(), codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
										}
										if(stack.search(neighbor_block) == -1) {
											stack.push(neighbor_block);
										}
									}
								}

							}
							
						}

					}else if( !(flowType.isJump()) && !(flowType.isCall())) {

						/*
						 * Se l'istruzione non è una JUMP né una CALL e consente il passaggio ad un altro blocco di codice
						 * siamo siamo in presenza della istruzione che termina il blocco corrente. Quindi, questo blocco
						 * di destinazione deve essere successivamente analizzato.
						 */

						if(referent_instr.getMnemonicString().contains("RET")) {
							printf("[ERRORE CONSISTENZA] Non è possibile che l'ultima istruzione sia una RET nel blocco [%x, %x] poiché esiste un seguito\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
							return -1;
						}
						if(func.getName().equals("FUN_00146400")) {
							printf("L'istruzione '%s' @ %x termina il blocco [%x, %x] e non è una CALL nè una JUMP\n", referent_instr.getMnemonicString(), referent_instr.getAddress().getOffset(), codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
						}

						if((neighbor_block.getMinAddress().getOffset() - base) < start_text || (neighbor_block.getMaxAddress().getOffset() - base) > end_text) {

							/* Con questa JUMP passiamo ad eseguire in una zona di codice in cui non ricerco le istruzioni di RET */
							is_in = 1;
							if(func.getName().equals("FUN_00146400")) {
								printf("Fuori sezione .text\n");
							}

						} else {

							/* Recupero la funzione a cui appartiene questo blocco di codice target */
							Function func_target = getFunctionContaining(neighbor_block.getFirstStartAddress());
					
							if(good_funcs.contains(func_target) && func_target != func) {
								is_in = 1;
							} else {
								if(stack.search(neighbor_block) == -1) {
									stack.push(neighbor_block);
								}
							}
						}	
					} else {
						if(func.getName().equals("FUN_00146400")) {
							printf("L'istruzione @ %x non è né una JUMP né una istruzione che termina il blocco\n", referent_instr.getAddress().getOffset());
						}
					}

				}	

			} catch(Exception e) {
				printf("[ERRORE RECUPERO SINGOLO VICINO] Errore nel recupero del blocco vicino [%x, %x]:\n%s\n", neighbor_block.getMinAddress().getOffset(), neighbor_block.getMaxAddress().getOffset(), e.getMessage());
				return -1;
			}

			/* Dopo aver identificato i vicini da visitare si passa ad esaminare il blocco corrente */

			/* Inizialmente assumo che il blocco corrente non termini con una istruzione di RET */
			ret_instr = false;
			
			/* Setto il numero di istruzioni di JUMP e di CALL che sono risolte da Ghidra e presenti nel blocco corrente */
			num_jumps = 0;
			num_calls = 0;

			/* Cerco le istruzioni di RET all'interno del blocco esterno corrente e verifico se il blocco termina in modo anomalo */

			try {

				/* Recupero l'indirizzo iniziale del blocco corrente che coincide con l'indirizzo della prima istruzione */
				currentAddress = codeBlock.getMinAddress();

				/* Itero su tutte le istruzioni presenti nel blocco corrente	*/

				while(currentAddress.compareTo(codeBlock.getMaxAddress()) <= 0 ) {

					/* Recupero la prossima istruzione da analizzare nel blocco corrente 			*/
					instruction = getInstructionAt(currentAddress);

					/* Verifico se rappresenta effettivamente una istruzione macchina 			*/
					if(instruction == null) {
						printf("[ERRORE RECUPERO ISTRUZIONE] Errore nel recupero dell'istruzione dal blocco [%x, %x]\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
						return -1;
					}

					/* Verifico se l'istruzione corrente è una RET per scrivere il suo offset nella lista	*/

					if(instruction.getMnemonicString().contains("RET")) {

						return_instruction_addr_list.add(instruction.getAddress().getOffset() - base);

						if(currentAddress.compareTo(codeBlock.getMaxAddress()) == 0) {
							ret_instr = true;
						} else {
							/* Questa printf la lascio per uno scopo di debugging			*/
							printf("[DFS] La funzione %s ha una RET che non è l'ultima istruzione nel blocco [%x, %x]\n", func.getName(), codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
						}

						/* Calcolo l'indirizzo dell'istruzione macchina successiva nel blocco corrente	*/
						currentAddress = currentAddress.add(instruction.getLength());

						continue;

					}

					/* Recupero la modalità con cui si passa alla successiva istruzione macchina		*/
					flowType = instruction.getFlowType();

					/* Verifico se l'istruzione macchina corrente è una tipologia di CALL	*/

					if( (flowType.isJump() || flowType.isCall()) && instruction.getMnemonicString().contains("CALL") ) {

						/* Recupero le destinazioni relative alla istruzione di CALL corrente			*/
						Reference[] references = instruction.getReferencesFrom();

						/* Verifico se Ghidra è stata in grado di risolvere la destinazione per la CALL corrente */

						if(references.length > 0) {

							/* Recupero i byte che codificano l'istruzione di CALL	*/
							CodeUnit codeunit = plist.getCodeUnitAt(instruction.getAddress());
							byte[] b = codeunit.getBytes();

							/*
							 * Le CALL con codice operativo 0xFF non contribuiscono per le frecce uscenti dal blocco di codice.
							 * Di conseguenza, non devo incrementare il contatore 'num_calls' altrimenti considererei delle
							 * frecce uscenti dal blocco di codice che non esistono.
							 */

							if(b[0] != (byte)0xFF) {
								num_calls = num_calls + 1;
							}else {
/*
								for(int r = 0; r < references.length; r++) {
									printf("Blocco [%x, %x] @%x Referenza #%d: %x\n", instruction.getAddress().getOffset(), codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), r + 1, references[r].getToAddress().getOffset());
								}
*/
							}					

						} else {
							//printf("[ERRORE RISOLUZIONE CALL] Ghidra non sa risolvere la CALL @%x nel blocco [%x, %x]\n", instruction.getAddress().getOffset(), codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
						}
						
						currentAddress = currentAddress.add(instruction.getLength());
						continue;
					}

					if(flowType.isJump() || (flowType.isTerminal() && (instruction.getMnemonicString().startsWith("J")))) {

						/* Recupero le destinazioni relative alla istruzione di salto corrente			*/
						Reference[] references = instruction.getReferencesFrom();

						if(references.length == 0) {

							/* Ghidra non è in grado di determinare le istruzioni successive che potrebbero essere delle RET */
							is_in = 1;

						} else {

							/* Per la corrente istruzione di JUMP Ghidra ha trovato almeno una destinazione */

							/* Registro il numero di frecce uscenti dal blocco di codice che produce questa JUMP	*/
							num_jumps = num_jumps + references.length;
						}
					}

	
					currentAddress = currentAddress.add(instruction.getLength());
				}

				/* Verifichiamo se il blocco corrente termina in modo anomalo */
				if(is_in == 0) {

					/* Recupero il numero totale di frecce uscenti dal blocco corrente */
					int numDest = codeBlock.getNumDestinations(monitor);

					flowType = instruction.getFlowType();

					if(flowType.isJump() && flowType.isConditional()) {

						/*
						 * Se l'ultima istruzione è un salto condizionale allora contribuirà con un '+2' a numDest. Infatti, essendo
						 * un salto CONDIZIONALE è possibile che esso non venga preso e che quindi l'esecuzione continui nel blocco
						 * contenente l'istruzione successiva. Quindi, abbiamo sia la freccia uscente associata al salto che la freccia
						 * uscente associata all'istruzione successiva nel 'normale' flusso di esecuzione. La freccia associata al salto
						 * effettivo è compresa nel valore della variabile 'num_jumps' poiché tutti i salti sono stati risolti, e quindi,
						 * il contributo addizionale sarà '+1'.
						 */

						if(numDest != (num_calls + num_jumps + 1)) {
							//printf("[DFS ETICHETTA JZ] Il blocco [%x, %x] termina in modo anomalo: %d %d %d\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), numDest, num_calls, num_jumps);
							is_in = 1;
						}

					} else if(ret_instr) {

					        /*
						 * Se l'ultima istruzione è una RET allora mi aspetto di trovare come numero di frecce uscenti dal blocco
						 * esattamente la somma dei due contatori. Infatti, non abbiamo un altro modo per uscire dal blocco.
						 */

						if(!(instruction.getMnemonicString().contains("RET"))) {
							printf("[DFS ERRORE RET] Il blocco [%x, %x] dovrebbe finire con una RET ma non ci termina...\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
							return -1;
						} else {
							if(numDest != (num_calls + num_jumps)) {
								//printf("[DFS ETICHETTA RET] Il blocco [%x, %x] termina in modo anomalo: %d %d %d\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), numDest, num_calls, num_jumps);
								is_in = 1;
							}
						}

					} else if(!(ret_instr) && !(flowType.isCall()) && !(flowType.isJump())) {

						/*
						 * Se l'ultima istruzione non è una RET/CALL/JUMP allora mi aspetto di trovare come numero di frecce uscenti
						 * dal blocco la somma dei due contatori più una ulteriore freccia uscente che punta al blocco dove è presente
						 * la successiva istruzione rispetto all'ultima presente nel blocco corrente.
						 */

						if(numDest != (num_calls + num_jumps + 1)) {
							//printf("[DFS ETICHETTA GENERICA] Il blocco [%x, %x] termina in modo anomalo: %d %d %d\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), numDest, num_calls, num_jumps);
							is_in = 1;
						}
					} else if(flowType.isCall() && instruction.getMnemonicString().contains("CALL")) {

						if(numDest != (num_jumps + num_calls + 1)) {
							//printf("[DFS ETICHETTA CALL] Il blocco [%x, %x] termina in modo anomalo: %d %d %d\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), numDest, num_calls, num_jumps);
							is_in = 1;
							num_call_in = num_call_in + 1;
						}
					}
				}


			} catch(Exception e) {
				printf("[ERRORE SCANSIONE DELLE ISTRUZIONI] Errore:\n%s\n", e.getMessage());
				return -1;
			}
		}

		if(func.getName().equals("FUN_00146400")) {
			printf("La funzione è di tipo IS_IN: %d\n", is_in);
		}

		return is_in;
    }

    /**
     * function_analysis - Esegue l'analisi della funzione identificando tutte le RET ed etichettandole insieme
     * alle istruzioni di CALL a tale funzione nel caso di possibili scenari IN. Nel momento in cui una JUMP
     * punta ad un blocco di codice che è esterno al Function Graph della funzione allora viene eseguita una
     * visita in profondità del grafo avente come blocco radice quello esterno al Function Graph.
     *
     * @func	       : Funzione di cui cercare le RET e di cui verificare se esistono possibili scenari IN
     * @base	       : Base scelta da Ghidra
     * @start_text     : Inizio della sezione .text
     * @end_text       : Fine della sezione .text
     * @blocks         : Lista dei blocchi di memoria che compongono il programma
     * @good_funcs     : Lista delle funzioni che rispettano gli iniziali criteri di filtraggio
     *
     * @return: Restituisce il valore 0 in caso di successo; altrimenti, restituisce il valore -1.
     */
    public int function_analysis(Function func, long base, long start_text, long end_text, MemoryBlock[] blocks, ArrayList<Function> good_funcs) {

		Instruction instruction = null;
		CodeBlockModel codeBlockModel;
		ArrayList<Long> return_instruction_addr_list;
		ArrayList<CodeBlock> codeBlockArray;
		boolean ret_instr;
		int num_jumps;
		int num_calls;
		ArrayList<CodeBlock> extern_blocks;
		boolean is_in_bool;
		int is_in;
		FlowType flowType;
		int counter;


		counter = 0;

		Listing plist = currentProgram.getListing();

		codeBlockModel = new BasicBlockModel(currentProgram);;

		/*
		 * Recupero tutti i blocchi di codice nel Function Graph della funzione corrente. Questa lista di blocchi
		 * verrà utilizzata per capire se uno specifico blocco di destinazione fa parte o meno del Function Graph
		 * della funzione corrente. L'obiettivo è trovare TUTTE le istruzioni di RET che sono presenti all'interno
		 * della funzione. Di conseguenza, se durante la sua esecuzione la funzione può seguire un percorso che va
		 * fuori dal grafo allora è necessario esaminarlo alla ricerca delle istruzioni di RET.
   		 */

		codeBlockArray = getCodeBlockArray(func);

		/*
		 * Nei blocci del FG della funzione corrente ci possono essere dei salti verso blocchi di codice che non
		 * fanno parte del FG. La ricerca delle RET deve considerare anche i grafi che hanno come radice questi
		 * blocchi di codice esterni. Dopo aver analizzato i blocchi del FG corrente si passa ad analizzare questi
		 * grafi 'esterni'. Utilizzo una lista per memorizzare i blocchi che saranno la radice dei grafi esterni e
		 * che potrebbero essere attraversati durante l'esecuzione della funzione.
		 */

		extern_blocks = new ArrayList<>();

		/* Istanzio un array per memorizzare gli offset delle istruzioni di RET presenti nella funzione corrente */
		return_instruction_addr_list = new ArrayList<Long>();

		/* Inizialmente assumo che la funzione non porti a scenari di tipo IN */
		is_in = 0;

		/* Come primo passo, itero su TUTTI i blocchi che compongono il FG della funzione */

		try {

			/* Costruisco l'iteratore sui blocchi di codice che compongono il Function Graph della funzione corrente */
			CodeBlockIterator codeBlockIterator = codeBlockModel.getCodeBlocksContaining(func.getBody(), monitor);

			/* Itero su tutti i blocchi nel FG della funzione corrente che sono stati identificati da Ghidra */

			while(codeBlockIterator.hasNext()) {

				/* Incremento il contatore dei blocchi visitati nel FG della funzione */
				counter = counter + 1;

				/* Recupero il successivo blocco nel FG da analizzare	*/
				CodeBlock codeBlock = codeBlockIterator.next();

				/* Recupero l'indirizzo iniziale del blocco corrente che coincide con l'indirizzo della prima istruzione */
				Address currentAddress = codeBlock.getMinAddress();

				/* Inizialmente assumo che il blocco corrente non termini con una istruzione di RET */
				ret_instr = false;

				/* 
				 * Conteggio delle istruzioni di JUMP e di CALL all'interno del blocco corrente per capire se esistono dei
				 * blocchi di codice nella funzione che terminano in modo anomalo. Se terminano in modo anomalo non sono in
				 * grado di cercare TUTTE le istruzioni di RET nella funzione. In questo caso, è necessario etichettare le
				 * CALL alla funzione e le RET nella funzione come 'possibili scenari IN'. Per quanto riguarda le istruzioni
				 * di salto, si considerano sia i salti CONDIZIONALI che quelli NON CONDIZIONALI per cui Ghidra è stata in
				 * grado di determinare la destinazione.
 				 */

				num_jumps = 0;
				num_calls = 0;

				/*
				 * Itero su tutte le istruzioni presenti nel blocco corrente del Function Graph. L'obiettivo è identificare
				 * tutte le istruzioni di RET che potrebbero essere eseguite tramite la funzione corrente. Se nel blocco è
				 * presente una istruzione di salto verso un blocco esterno al Function Graph allora è necessario percorrere
				 * tutti i cammini che hanno come radice questo blocco esterno alla ricerca delle RET. Se uno di questi
				 * cammini dovesse terminare in modo anomalo allora le CALL a questa funzione e le RET che essa potrebbe
				 * eseguire dovranno essere etichettate come 'possibili scenari IN'.
				 */

				while(currentAddress.compareTo(codeBlock.getMaxAddress()) <= 0 ) {

					/* Recupero la prossima istruzione da analizzare nel blocco corrente */
					instruction = getInstructionAt(currentAddress);

					/* Verifico se rappresenta effettivamente una istruzione macchina */
					if(instruction == null) {
						printf("[ERRORE RECUPERO ISTRUZIONE] Errore nel recupero dell'istruzione dal blocco [%x, %x]\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
						return -1;
					}

					/* Verifico se l'istruzione corrente è una RET per scrivere il suo offset nella lista	*/

					if(instruction.getMnemonicString().contains("RET")) {

						/* Memorizzo l'offset della RET nella lista tenendo conto della base utilizzata da Ghidra */
						return_instruction_addr_list.add(instruction.getAddress().getOffset() - base);

						/*
						 * Verifico se l'istruzione di RET è l'ultima istruzione nel blocco corrente. Questa informazione verrà
						 * utilizzata per stabilire se un blocco termina in modo anomalo. Se è presente una RET nel blocco come
						 * ultima istruzione, allora avrò una freccia in meno uscente dal blocco corrente poiché l'esecuzione
						 * della funzione terminerà a seguito della istruzione di RET.
						 */

						if(currentAddress.compareTo(codeBlock.getMaxAddress()) == 0) {
							ret_instr = true;
						} else {
							/* Questa printf la lascio per uno scopo di debugging e per vedere se è possibile questo caso */
							printf("La funzione %s ha una RET che non è l'ultima istruzione nel blocco [%x, %x]\n", func.getName(), codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
						}

						/* Calcolo l'indirizzo dell'istruzione macchina successiva nel blocco corrente	*/
						currentAddress = currentAddress.add(instruction.getLength());

						/* Passo all'istruzione macchina successiva	*/
						continue;
					}

					/* Recupero la modalità con cui si passa alla successiva istruzione macchina		*/
					flowType = instruction.getFlowType();

					/*
					 * Verifico se l'istruzione corrente è una tipologia di CALL. Osservo che esistono delle CALL che Ghidra
					 * non è in grado di risolvere staticamente. Differentemente dalle istruzioni di JUMP, se una CALL non è
					 * risolvibile da Ghidra allora non devo etichettare le istruzioni. Infatti, quando devo instrumentare una
					 * funzione si modificheranno le RET nella funzione e le CALL a tale funzione. Quindi, se nella funzione
					 * esistono delle CALL che Ghidra non sa risolvere allora questo non è un problema. Infatti, tutto ciò NON
					 * porta a scenari di tipo IN ma, al più, a scenari di tipo NI che non lasciano residui sullo stack kernel.
					 * Osservo che questo check su una eventuale istruzione di CALL viene fatto esclusivamente con lo scopo di
					 * identificare una terminazione anomala della funzione nel corrente blocco. Devo incrementare il contatore
					 * solamente se la destinazione della CALL è risolta da Ghidra e se a tale destinazione corrisponde una
					 * freccia uscente dal blocco di codice corrente.
					 */

					if( (flowType.isJump() || flowType.isCall()) && instruction.getMnemonicString().contains("CALL") ) {

						/* Recupero le destinazioni relative alla istruzione di CALL corrente			*/
						Reference[] references = instruction.getReferencesFrom();

						/* Verifico se Ghidra è stata in grado di risolvere la destinazione per la CALL corrente */

						if(references.length > 0) {

							/* Recupero i byte che codificano l'istruzione di CALL	*/
							CodeUnit codeunit = plist.getCodeUnitAt(instruction.getAddress());
							byte[] b = codeunit.getBytes();

							/*
							 * Le CALL con codice operativo 0xFF non contribuiscono per le frecce uscenti dal blocco di codice.
							 * Di conseguenza, non devo incrementare il contatore 'num_calls' altrimenti considererei delle
							 * frecce uscenti dal blocco di codice che non esistono.
							 */

							if(b[0] != (byte)0xFF) {
								num_calls = num_calls + 1;
							}else {
/*
								for(int r = 0; r < references.length; r++) {
									printf("Blocco [%x, %x] @%x Referenza #%d: %x\n", instruction.getAddress().getOffset(), codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), r + 1, references[r].getToAddress().getOffset());
								}
*/
							}			

						} else {
							//printf("[ERRORE RISOLUZIONE CALL] Ghidra non sa risolvere la CALL @%x nel blocco [%x, %x]\n", instruction.getAddress().getOffset(), codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
						}
						
						currentAddress = currentAddress.add(instruction.getLength());
						continue;
					}

					/*
					 * Per trovare tutte quante le RET che possono essere eseguite tramite questa funzione, è
					 * necessario verificare se i blocchi target delle istruzioni di salto verranno analizzati.
					 * Se questi blocchi target fanno parte del FG allora sicuramente sono stati già analizzati
					 * oppure verranno successivamente analizzati. Tuttavia, se sono esterni al FG allora si ha
					 * la necessità di registrare in una lista questi blocchi e successivamente percorrere tutti
					 * i cammini che hanno tali blocchi come punto di partenza.
					 * Verifico se l'istruzione corrente è una tipologia di salto. In questo caso, è possibile
					 * avere i seguenti scenari:
					 * 1. Ghidra non è in grado di determinare la/le destinazione/i del salto
					 * 2. Ghidra è in grado di determinare la/le destinazione/i del salto:
					 *	2.1. e il blocco target fa parte del Function Graph relativo alla funzione corrente.
					 *	2.2. e il blocco target è esterno al Function Graph relativo alla funzione corrente.
					 * E' necessario esaminare le istruzioni contenute in TUTTI i possibili blocchi di codice che
					 * potrebbero essere eseguiti dalla funzione. Per catturare tutte le istruzioni di salto è
					 * necessario utilizzare entrambi i metodi isJump() e isCall().
			  		 */

					if((flowType.isJump() || flowType.isCall()) && (instruction.getMnemonicString().startsWith("J"))) {

						/* Recupero le destinazioni relative alla istruzione di salto corrente			*/
						Reference[] references = instruction.getReferencesFrom();

						/*
						 * Un salto potrebbe avere anche più di una destinazione. In questo caso, bisogna considerare tutti questi
						 * percorsi alla ricerca delle istruzioni di RET. Ad esempio, una istruzione di JMP potrebbe essere usata
						 * per implementare un costrutto 'switch'. In questo caso, abbiamo una destinazione per ogni possibile caso
						 * dello switch.
						 */

						if(references.length == 0) {

							/*
							 * Ghidra non è in grado di risolvere la destinazione per il salto corrente. Di conseguenza, se la
							 * funzione corrente seguisse questo percorso allora potrebbe raggiungere una istruzione di RET che
							 * non siamo stati in grado di identificare. E' necessario etichettare le CALL a questa funzione e
							 * le RET nella funzione come 'possibili scenari IN' poiché non conosco il codice che verrà eseguito 
							 * dopo questa istruzione di JUMP.
							 */

							//printf("Funzione: %s\n", func.getName());
							//printf("La JMP @%x non ha alcuna destinazione...\n", instruction.getAddress().getOffset());
							//printf("Il blocco contenente questa JMP ha range [%x, %x]\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());

							is_in = 1;

						} else {

							/* Per la corrente istruzione di JUMP Ghidra ha trovato almeno una destinazione */

                            				if(func.getName().equals("FUN_00147020")) {
							    printf("Funzione: %s\n", func.getName());
							    printf("Il numero di riferimenti per la JMP '%s' @%x è %d\n", instruction.getMnemonicString(), instruction.getAddress().getOffset() - base, references.length);
							    printf("Il blocco contenente questa JMP ha range [%x, %x]\n", codeBlock.getMinAddress().getOffset() - base, codeBlock.getMaxAddress().getOffset() - base);
                            				}

							/*
							 * Itero su tutte le destinazioni del salto per verificare se il blocco target è esterno al Function
							 * Graph corrente. In questo caso, bisogna percorrere tutti questi cammini alla ricerca delle istruzioni
							 * di RET.
						         */

							/* Registro il numero di frecce uscenti dal blocco di codice che produce questa JUMP	*/
							num_jumps = num_jumps + references.length;
		
							/* Itero su tutte le destinazioni del salto	*/
							for(int i=0; i<references.length; i++) {

								/* Recupero il blocco di codice che contiene l'istruzione target del salto		*/
								CodeBlock codeBlockTarget = codeBlockModel.getCodeBlockAt(references[i].getToAddress(), monitor);

								if(func.getName().equals("FUN_00147020")) {
									printf("Blocco target del salto [%x, %x]\n", codeBlockTarget.getMinAddress().getOffset(), codeBlockTarget.getMaxAddress().getOffset());
								}

								/* Verifico se il blocco target è esterno al Function Graph della funzione corrente	*/

								if(!(codeBlockArray.contains(codeBlockTarget))) {

									/*
									 * Devo evitare di seguire percorsi che sono esterni alla sezione .text. Ad esempio, spesso le chiamate
									 * alle funzioni di libreria esterne che passano tramite la .plt avvengono nel seguente modo:
									 * 1. CALL ad una funzione DUMMY presente nella sezione .text.
									 * 2. Questa funzione contiene una istruzione di JMP alla .plt.
									 * 3. La entry della .plt contiene una istruzione di JMP alla funzione di libreria esterna.
									 * Ovviamente, il blocco di codice a cui si passa il controllo tramite la JMP del passo (2) è esterno alla
									 * sezione .text. Poiché la ricerca delle RET avviene solamente all'interno della sezione .text che contiene
									 * il codice del nostro programma, non sono in grado di identificare le RET presenti al di fuori di tale
									 * sezione, soprattutto se queste funzioni appartengono a librerie esterne. Di conseguenza, devo etichettare
									 * le CALL e le RET come possibili scenari di tipo 'IN'.
									 */

									if((codeBlockTarget.getMinAddress().getOffset() - base) < start_text || (codeBlockTarget.getMaxAddress().getOffset() - base) > end_text) {

										/* Sto uscendo dalla sezione .text... si potrebbero avere degli scenari di tipo IN */

										if(func.getName().equals("FUN_00147020")) {
											printf("Funzione: %s\n", func.getName());
											printf("Il numero di riferimenti per la JMP '%s' @%x è %d\n", instruction.getMnemonicString(), instruction.getAddress().getOffset(), references.length);
											printf("Il blocco contenente questa JMP ha range [%x, %x]\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
											printf("Il blocco di codice che sembrerebbe essere esterno alla sezione .text è [%x, %x]\n", codeBlockTarget.getMinAddress().getOffset(), codeBlockTarget.getMaxAddress().getOffset());
											for(int k=0; i<blocks.length;k++) {
												if((codeBlockTarget.getMinAddress().getOffset() >= blocks[k].getStart().getOffset()) && (codeBlockTarget.getMaxAddress().getOffset() <= blocks[k].getEnd().getOffset())) {
													printf("Il blocco esterno è presente nella sezione '%s'\n", blocks[k].getName());
													break;
												}
											}
										}

										is_in = 1;

									} else {

										/*
										 * Questo blocco di codice è esterno al Function graph della funzione corrente ma è presente nella sezione .text.
										 * Questo blocco di codice che viene eseguito tramite una istruzione di JUMP non può appartenenre ad alcuna funzione
										 * riconosciuta da Ghidra e che rispetta i criteri di filtraggio (i.e., è una buona funzione da instrumentare). Infatti,
										 * se appartenesse ad un'altra funzione rischierei di instrumentare delle RET che non è detto debbano essere instrumentate.
										 * Inserisco il blocco di codice nella lista per esaminare successivamente tutti i percorsi che lo hanno come radice.
										 * Il blocco verrà inserito nella lista solamente se non è già presente. Infatti, è possibile che più istruzioni di
										 * salto all'interno della funzione abbiano lo stesso blocco di destinazione. 
										 */

										/* Recupero la funzione a cui appartiene questo blocco di codice target */
										Function func_target = getFunctionContaining(codeBlockTarget.getFirstStartAddress());
					
										if(good_funcs.contains(func_target) && func_target != func) {
											is_in = 1;
										} else {
											if(!(extern_blocks.contains(codeBlockTarget))) {
												if(func.getName().equals("FUN_00147020")) {
													printf("Blocco esterno al FG della funzione %s: [%x, %x]\n", "FUN_00147020", codeBlockTarget.getMinAddress().getOffset(), codeBlockTarget.getMaxAddress().getOffset());
												}
												extern_blocks.add(codeBlockTarget);
											}
										}

									}
								}
							}
						}
					}

					/* Calcolo l'indirizzo dell'istruzione successiva nel blocco corrente			*/
					currentAddress = currentAddress.add(instruction.getLength());
				}

				/*
				 * Dopo aver iterato sulle istruzioni presenti nel blocco corrente ho identificato le eventuali istruzioni di RET.
				 * Se nel blocco è stato trovato un salto che Ghidra non è in grado di risolvere oppure un salto verso del codice
				 * che è al di fuori della sezione .text allora sappiamo già di dover etichettare le istruzioni di CALL e di RET
				 * come possibili scenari IN.
				 * Tuttavia, è possibile che non sia successo nulla di tutto ciò ma che il blocco corrente potrebbe terminare in
				 * modo anomalo. Una funzione termina in modo anomalo se l'ultimo blocco non contiene una RET come ultima istruzione
				 * e Ghidra non riesce a trovare l'istruzione successiva. In questo caso, dobbiamo etichettare le istruzioni come
				 * possibili scenari di tipo IN. Inoltre, osservo che se 'is_in' == 0 allora tutti i salti che sono presenti nel
				 * blocco di codice corrente hanno una destinazione risolta da Ghidra.
				 */

				if(is_in == 0) {

					/* Recupero il numero totale di frecce uscenti dal blocco corrente nel FG */
					int numDest = codeBlock.getNumDestinations(monitor);

					/* Recupero il modo con cui dall'ultima istruzione del blocco passo alla successiva */
					flowType = instruction.getFlowType();

					/* Non considero il caso in cui l'ultima istruzione è una JMP poiché è stato già trattato (non riesce a risolvere il salto) */

					if(flowType.isJump() && flowType.isConditional()) {

						/*
						 * Se l'ultima istruzione è un salto condizionale allora contribuirà con un '+2' a numDest. Infatti, essendo
						 * un salto CONDIZIONALE è possibile che esso non venga preso e che quindi l'esecuzione continui nel blocco
						 * contenente l'istruzione successiva. Quindi, abbiamo sia la freccia uscente associata al salto che la freccia
						 * uscente associata all'istruzione successiva nel 'normale' flusso di esecuzione. La freccia associata al salto
						 * effettivo è compresa nel valore della variabile 'num_jumps' poiché tutti i salti sono stati risolti, e quindi,
						 * il contributo addizionale sarà '+1'.
						 */

						if(numDest != (num_calls + num_jumps + 1)) {
							//printf("[ETICHETTA JZ] Il blocco [%x, %x] termina in modo anomalo: %d %d %d\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), numDest, num_calls, num_jumps);
							is_in = 1;
						}

					} else if(ret_instr) {

					        /*
						 * Se l'ultima istruzione è una RET allora mi aspetto di trovare come numero di frecce uscenti dal blocco
						 * esattamente la somma dei due contatori. Infatti, non abbiamo un altro modo per uscire dal blocco se non
						 * tramite una CALL oppure una JUMP.
						 */

						if(!(instruction.getMnemonicString().contains("RET"))) {
							printf("[ERRORE RET] Il blocco [%x, %x] dovrebbe finire con una RET ma non ci termina...\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset());
							return -1;
						} else {
							if(numDest != (num_calls + num_jumps)) {
								//printf("[ETICHETTA RET] Il blocco [%x, %x] termina in modo anomalo: %d %d %d\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), numDest, num_calls, num_jumps);
								is_in = 1;
							}
						}

					} else if(!(ret_instr) && !(flowType.isCall()) && !(flowType.isJump())) {

						/*
						 * Se l'ultima istruzione non è una RET/CALL/JUMP allora mi aspetto di trovare come numero di frecce uscenti
						 * dal blocco la somma dei due contatori più una ulteriore freccia uscente che punta al blocco dove è presente
						 * la successiva istruzione rispetto all'ultima presente nel blocco corrente.
						 */

						if(numDest != (num_calls + num_jumps + 1)) {
							//printf("[ETICHETTA GENERICA] Il blocco [%x, %x] termina in modo anomalo: %d %d %d\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), numDest, num_calls, num_jumps);
							is_in = 1;
						}
					} else if(flowType.isCall() && instruction.getMnemonicString().contains("CALL")) {

						if(numDest != (num_jumps + num_calls + 1)) {
							//printf("[ETICHETTA CALL] Il blocco [%x, %x] termina in modo anomalo: %d %d %d\n", codeBlock.getMinAddress().getOffset(), codeBlock.getMaxAddress().getOffset(), numDest, num_calls, num_jumps);
							is_in = 1;
							num_call_in = num_call_in + 1;
						}
					}
				}
			}
		} catch (Exception e) {
			printf("Errore durante l'iterazione sui blocchi e sulle istruzioni:\n%s\n", e.getMessage());
			return -1;
		}

		/* Verifico se ho considerato effettivamente tutti i blocchi nel FG della funzione */
		if(counter != codeBlockArray.size()) {
			printf("[ERRORE CONSISTENZA] Ci sono dei blocchi nella funzione %s che non vengono considerati\n", func.getName());
			return -1;
		}
		
		/*
		 * Durante la scansione dei blocchi nel FG è possibile che siano stati identificati alcuni blocchi esterni.
		 * A questo punto, viene eseguita una visita in profondità di tutti i grafi aventi come radice i blocchi
		 * all'interno della lista 'extern_blocks'. L'obiettivo è trovare tutte le RET che possono essere eseguite
		 * dalla funzione e verificare se esiste la possibilità di avere degli scenari di tipo IN.
		 */

		int is_in_ext;

		/* Itero su tutti i blocchi di destinazione che sono esterni al FG ma che possono essere eseguiti dalla funzione */

		for(int v = 0; v < extern_blocks.size(); v++) {

			CodeBlock curr_block = extern_blocks.get(v);

			//printf("Funzione: %s\n", func.getName());

			//printf("[ITERAZIONE] Nel FG si salta al grafo avente come radice il blocco esterno [%x, %x]\n",  curr_block.getMinAddress().getOffset(), curr_block.getMaxAddress().getOffset());

			/* Eseguo una visita in profondità del grafo avente come radice il blocco di codice esterno corrente	*/
			is_in_ext = DFS_iterative(curr_block, return_instruction_addr_list, base, codeBlockModel, func, start_text, end_text, good_funcs);

			if(is_in_ext == -1) {
				printf("[ERRORE DFS] Errore nella visita in profondità del grafo con radice [%x, %x]\n", curr_block.getMinAddress().getOffset(), curr_block.getMaxAddress().getOffset());
				return -1;
			} else if(is_in_ext == 1) {
				//TODO: Etichetta le CALL a questa funzione e le RET che contiene come possibili scenari di tipo IN
				is_in = 1;
				//printf("Il blocco con range [%x, %x] inizia dei cammini che NON terminano correttamente\n", curr_block.getMinAddress().getOffset(), curr_block.getMaxAddress().getOffset());
			} else {
				//printf("Il blocco con range [%x, %x] inizia dei cammini che terminano correttamente\n", curr_block.getMinAddress().getOffset(), curr_block.getMaxAddress().getOffset());
			}
		}

		//TODO: Filtrare le funzioni che non hanno alcuna RET? Perché altrimenti avrei necessariamente uno scenario IN oppure NN.

		if(return_instruction_addr_list.size() == 0) {
			printf("La funzione %s che aveva superato i criteri di filtraggio iniziali non ha alcuna RET\n", func.getName());
			return 0;
		}

		/* Inserisco la funzione che rispetta TUTTI i criteri di filtraggio che sono stati adottati */
		final_good_funcs.add(func);

		/* Memorizzo gli offset delle istruzioni di RET che possono essere eseguite dalla funzione */
		ret_addr_funcs.add(return_instruction_addr_list);

		for(int i=0; i<good_funcs.size(); i++){
			if(func.getName().equals(good_funcs.get(i).getName())) {
				final_call_reference_addresses.add(call_reference_addresses.get(i));
				break;
			}
		}

		/* Devo stabilire se le CALL alla funzione e le RET della funzione devono essere etichettate come possibili scenari IN */
		if(is_in == 1) {
			func_is_in_list.add(true);
		} else {
			func_is_in_list.add(false);
		}

		return 0;
    }


    /**
     * search_call_instr - Ricerca tutte le istruzioni di CALL 0xE8 alla funzione richiesta. Gli indirizzi
     * di queste istruzioni di CALL vengono salvati all'interno della lista passata come parametro.
     *
     * @func	      : La funzione di cui voglio trovale le CALL 0xE8 che la invocano
     * @plist	      : Istanza di Listing
     * @call_reference: Array contenente gli offset delle istruzioni di CALL 0xE8 da riempire
     * @base	      : Base scelta da Ghidra
     */	
    public void search_call_instr(Function func, Listing plist, ArrayList<Long> call_reference, long base) {
		int good;
		ReferenceManager referenceManager;
		ReferenceIterator referenceIterator;

		/* Recupero il riferimento al gestore delle referenze per il programma corrente */
		referenceManager = currentProgram.getReferenceManager();

		/* Recupero tutti i riferimenti alla funzione corrente */
		referenceIterator = referenceManager.getReferencesTo(func.getEntryPoint());

		/* Questa variabile vale 1 se esiste almeno una CALL 0xE8 alla funzione richiesta */
		good = 0;

		/* Itero sui vari riferimenti alla funzione */
		while(referenceIterator.hasNext()) {

			/* Prendo il prossimo riferimento alla funzione	*/
			Reference reference = referenceIterator.next();

			/* Verifico se il riferimento alla funzione viene fatto tramite una CALL 0xE8 */

			if(reference.getReferenceType().isCall())  {

				/* Recupero l'indirizzo della istruzione di CALL relativa al riferimento corrente */
				Address callAddress = reference.getFromAddress();
				long callAddressValue = callAddress.getOffset();

				try {
					/* Recupero l'istruzione di CALL corrente */
					Instruction ins = getInstructionAt(callAddress);

					/* Recupero i byte utilizzati per la codifica dell'istruzione di CALL */
					CodeUnit codeUnit = plist.getCodeUnitAt(callAddress);
					byte[] opcode = codeUnit.getBytes();

					/*
					 * Verifico se questa CALL è effettivamente una CALL relativa con codice operativo 0xE8. E'
					 * necessario verificare se l'istruzione contenga la stringa 'CALL' poiché ci sono dei casi
					 * in cui Ghidra fa restituire 'True' al metodo 'isCall()' anche se abbiamo delle istruzioni
					 * di JUMP.
					 */

					if(ins != null) {

						if(!(ins.getMnemonicString().contains("CALL")) || opcode[0] != (byte)0xE8) {
							/* Passo al riferimento successivo */
							continue;
						} else {

							/* Memorizzo l'indirizzo della istruzione di CALL 0xE8  per il Loader ELF */

							if(!(call_reference.contains(callAddressValue))) {
								call_reference.add(callAddressValue - base);
							}
						}
					}

				} catch(Exception e) {
					printf("[ERRORE RICERCA CALL] Errore nella ricerca delle istruzioni di CALL per la funzione %s:\n%s\n", func.getName(), e.getMessage());
				}
			}
		}
    }


    public void run() throws Exception {
		int ret;
		int counter_func;								/* Contatore delle funzioni */
		long base;									/* Indirizzo base scelto da Ghidra */
		long end_text;									/* Indirizzo finale della sezione .text */
		long start_text;								/* Indirizzo iniziale della sezione .text */
		MemoryBlock[] blocks;								/* Lista dei blocchi di memoria del programma corrente */
		ArrayList<Function> good_funcs = new ArrayList<>();				/* Liste delle funzioni che rispettano i criteri iniziali di filtraggio */
		Listing plist;
		FlatProgramAPI fpapi;


		fpapi = new FlatProgramAPI(currentProgram);

		plist = currentProgram.getListing();

		/* Recupero l'indirizzo base scelto da Ghidra                                                                   */
		base = currentProgram.getMinAddress().getOffset();

		/* Recupero tutti i blocchi di memoria nel programma                                                            */
		blocks = currentProgram.getMemory().getBlocks();

		/* Inizializzo gli estremi della sezione .text che verranno utilizzati per filtrare le funzioni di interesse    */
		start_text = 0;
		end_text = start_text;

		/* Recupero gli estremi della sezione .text                                                                     */
		for(int i=0; i<blocks.length;i++) {
			if(blocks[i].getName().equals(".text")) {
				start_text = blocks[i].getStart().getOffset();
				end_text = blocks[i].getEnd().getOffset();
				printf("La sezione .text si trova nel range di indirizzi: [%x, %x]\n", start_text - base, end_text - base);
			}
		}

		/* Verifico se è stata trovata la sezione .text del programma							*/
		if(start_text == end_text) {
			printf("[ERRORE RECUPERO RANGE .text] La sezione .text non è stata trovata nell'eseguibile corrente\n");
			return;
		}

        	/*
         	* Ghidra riconosce tutte le funzioni all'interno dell'eseguibile. Tuttavia, ci sono dei blocchi di codice che
         	* sono riconosciuti come funzioni ma che in realtà potrebbero non esserlo. Vengono applicati dei criteri di
         	* filtraggio con l'obiettivo di considerare solamente delle 'buone' funzioni. Itero su tutte le funzioni nel
         	* programma applicando ad ognuna di esse i criteri di filtraggio.
         	*/

		/* Recupero la prima funzione del programma */
		Function func = getFirstFunction();

		/* Inizializzo il contatore delle funzioni */
		counter_func = 0;

		/* Itero sulle funzioni presenti nel programma applicando un insieme di criteri	*/
		while(func != null && !monitor.isCancelled()) {

			counter_func = counter_func + 1;

			/* Recupero gli estremi della funzione identificata da Ghidra  */ 
			long max_addr_func = func.getBody().getMaxAddress().getOffset();
			long min_addr_func = func.getBody().getMinAddress().getOffset();
			
			/* Verifico se la funzione cade nella sezione .text e se è presente almeno una istruzione */

			if(min_addr_func >= start_text && max_addr_func <= end_text && min_addr_func < max_addr_func) {

				/* Verifico se la funzione inizia con un'istruzione ENDBR64 */

				if(fpapi.getInstructionContaining(func.getEntryPoint()).getMnemonicString().equals("ENDBR64") || fpapi.getInstructionContaining(func.getEntryPoint()).getMnemonicString().equals("PUSH")) {

					/* Questo array contiene gli indirizzi delle CALL 0xE8 alla funzione corrente */
					ArrayList<Long> call_reference = new ArrayList<>();

					/* Recupero tutte le CALL 0xE8 a questa funzione */
					search_call_instr(func, plist, call_reference, base);
	
					/* Verifico se esiste almeno una CALL 0xE8 a questa funzione */

					if(call_reference.size() > 0) {

						/* La funzione corrente rispetta i criteri di filtraggio considerati finora */
						good_funcs.add(func);

						/* Memorizzo gli offset di tutte le CALL 0xE8 a questa funzione in modo che siano utilizzabili dal Loader ELF */
						call_reference_addresses.add(call_reference);
/*
						printf("Lista delle istruzioni di CALL 0xE8 per la funzione %s:\n", func.getName());
						for(int k = 0; k < call_reference.size(); k++) {
							printf("CALL #%d: %x\n", k + 1, call_reference.get(k));
						}
						printf("\n");
*/
					} else {
						//printf("Non esiste alcuna CALL 0xE8 alla funzione %s\n", func.getName());
					}
				}
			}
			
			/* Passo alla funzione successiva nel programma	*/
			func = getFunctionAfter(func);
		}

		printf("Numero totale delle funzioni: %d	Numero delle funzioni che rispettano i criteri di filtraggio: %d\n", counter_func, good_funcs.size());

		if(call_reference_addresses.size() != good_funcs.size()) {
			printf("[ERRORE CONSISTENZA] Esistono delle funzioni di cui non conosco le istruzioni di CALL che le invocano\n");
			return;
		}

		/*
		 * Arrivato a questo punto sono riuscito a filtrare le funzioni riconosciute da Ghidra e ho ricavato tutte
		 * le istruzioni di CALL 0xE8 verso queste funzioni. Tuttavia, mancherebbe l'applicazione di un ultimo criteri
		 * di filtraggio che consente nello scartare le funzioni che non hanno alcuna istruzione di RET. Per applicare
		 * questo criterio di filtraggio è necessario trovare tutte le istruzioni di RET che potrebbero essere eseguite
		 * dalla funzione. Ghidra non esporta alcuna API che consente di trovare le RET. Di conseguenza, prima ricerco
		 * tutte le istruzioni di RET che possono essere eseguite da queste funzioni e successivamente applico il criterio.
		 * Inoltre, memorizzo la posizione di queste RET all'interno dell'eseguibile e verifico se è necessario etichettare
		 * le istruzioni di CALL a tali funzioni e le istruzioni RET presenti in tali funzioni come possibili scenari IN.
		 */

		for(int index = 0; index < good_funcs.size(); index++) {
			ret = function_analysis(good_funcs.get(index), base, start_text - base, end_text - base, blocks, good_funcs);
			if(ret == -1) {
				printf("[ERRORE ANALISI] Si è verificato un errore durante l'analisi della funzione %s\n", good_funcs.get(index).getName());
				return;
			}
		}

		if( (final_good_funcs.size() != func_is_in_list.size()) || (final_good_funcs.size() != ret_addr_funcs.size())) {
			printf("[ERRORE CONSISTENZA] Errore nel ricavare le informazioni per le varie funzioni\n");
			return;
		}

		int count_is_in = 0;

		/* Conto le istruzioni che potrebbero portare a degli scenari di tipo IN */
		for(int i = 0; i < func_is_in_list.size(); i++) {
			if(func_is_in_list.get(i) == true) {
				count_is_in = count_is_in + 1;
			}
		}

		printf("Numero di funzioni con possibili scenari IN: %d\n", count_is_in);

		/* Scrivo su file le informazioni di instrumentazione */
		ret = save_instruction_on_file(start_text - base, end_text - base, final_good_funcs, count_is_in);

		if(ret == -1){
			printf("[ERRORE FILE] Errore nella scrittura delle informazioni di instrumentazione su File\n");
			return;
		}
		
    }

}

