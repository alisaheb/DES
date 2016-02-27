/**
 * This class can encrypt input.txt content with the key of key.txt.
 * And this encrypted text store in hexadecimal format in output.txt.   
 * This class can also decrypt the generated output with the same key key.txt.
 * All this encryption and Decryption done by Des Algorithm.   
 *   
 * @category Ali Saheb 
 * @author Ali Saheb 
 * @since 1.0.0
 * @see
 * @link  http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
 */

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Scanner;

public class DES {
	 /**
     * This variable hold the permutation choice one table of DES
     * @var byte[] PC1 This is to hold permutation choice one
     */
		private static final byte[] PC1 = {
			57, 49, 41, 33, 25, 17, 9,
			1,  58, 50, 42, 34, 26, 18,
			10, 2,  59, 51, 43, 35, 27,
			19, 11, 3,  60, 52, 44, 36,
			63, 55, 47, 39, 31, 23, 15,
			7,  62, 54, 46, 38, 30, 22,
			14, 6,  61, 53, 45, 37, 29,
			21, 13, 5,  28, 20, 12, 4
		};
		
		/**
	     * This variable hold the permutation choice two table of DES
	     * @var byte[] PC2 This is to hold permutation choice two
	     */		
		private static final byte[] PC2 = {
			14, 17, 11, 24, 1,  5,
			3,  28, 15, 6,  21, 10,
			23, 19, 12, 4,  26, 8,
			16, 7,  27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32
		};
		
		/**
	     * Rotations control the left shift number of every round of DES
	     * @var byte[] rotations hold the left  shift number 
	     */
		private static final byte[] rotations = {
			1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
		};	
		/**
	     * This variable hold the left 28 of key 
	     * @var int[] C 
	     */
		private static int[] C = new int[28];
		/**
	     * This variable hold the Right 28 of key 
	     * @var int[] D 
	     */
		private static int[] D = new int[28];
		/**
	     * This variable is two dimensional array to store the round key of DES
	     * @var int[][] keyStore 
	     */
		private static int[][] keyStore = new int[16][48];
		
		/**
	     * This variable hold the initial permutation for DES  
	     * @var byte[] IP 
	     */
		private static final byte[] IP = { 
				58, 50, 42, 34, 26, 18, 10, 2,
				60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6,
				64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17, 9,  1,
				59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5,
				63, 55, 47, 39, 31, 23, 15, 7
			};
		/**
	     * This variable hold the S box which is very important for DES   
	     * @var byte[][] S
	     */
		private static final byte[][] S = { {
			14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7,
			0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8,
			4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0,
			15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13
		}, {
			15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10,
			3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5,
			0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15,
			13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9
		}, {
			10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
			13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
			13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
			1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12
		}, {
			7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15,
			13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9,
			10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4,
			3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14
		}, {
			2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9,
			14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6,
			4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14,
			11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3
		}, {
			12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
			10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
			9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
			4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13
		}, {
			4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1,
			13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6,
			1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2,
			6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12
		}, {
			13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
			1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
			7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
			2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11
		} };
		/**
	     * This variable hold E box which work for  32 to 48 bit conversion of input bits  
	     * @var byte[] E
	     */
		private static final byte[] E = {
				32, 1,  2,  3,  4,  5,
				4,  5,  6,  7,  8,  9,
				8,  9,  10, 11, 12, 13,
				12, 13, 14, 15, 16, 17,
				16, 17, 18, 19, 20, 21,
				20, 21, 22, 23, 24, 25,
				24, 25, 26, 27, 28, 29,
				28, 29, 30, 31, 32, 1
			};
		/**
	     * This variable hold P box   
	     * @var byte[] P
	     */
		private static final byte[] P = {
				16, 7,  20, 21,
				29, 12, 28, 17,
				1,  15, 23, 26,
				5,  18, 31, 10,
				2,  8,  24, 14,
				32, 27, 3,  9,
				19, 13, 30, 6,
				22, 11, 4,  25
			};
		/**
	     * This variable final permutation table    
	     * @var byte[] FP
	     */
		private static final byte[] FP = {
				40, 8, 48, 16, 56, 24, 64, 32,
				39, 7, 47, 15, 55, 23, 63, 31,
				38, 6, 46, 14, 54, 22, 62, 30,
				37, 5, 45, 13, 53, 21, 61, 29,
				36, 4, 44, 12, 52, 20, 60, 28,
				35, 3, 43, 11, 51, 19, 59, 27,
				34, 2, 42, 10, 50, 18, 58, 26,
				33, 1, 41, 9, 49, 17, 57, 25
			};

		
		 /**
		  * This is the main function of DES this function can do encryption and decryption.
		  *
		  * @author Ali Saheb           
		  * @param String [] args		  
		  * @return void
		  * @since 1.0.0
		  * @see  
		  */
	
	public static void main(String []args) throws IOException{
		 
		int keybit[] = new int[64];
		keybit = Key();
		int i;
		for(i=0 ; i < 28 ; i++) {
			C[i] = keybit[PC1[i]-1];
		}
		for( ; i < 56 ; i++) {
			D[i-28] = keybit[PC1[i]-1];
		}
		
		for(int round= 0;round<16;round++){
			subkey(round);
		}
		
		int afterIP[];
		afterIP = finalResulrEnc();
		printfunc(afterIP);
		readOutputFromFile();
		finalDecription();	
	}
	
	 /**
	  * Key method read the key.txt and return a binary bit of the key which provide by the key.txt.
	  *
	  * @author Ali Saheb           	  		  
	  * @return Records of integer array
	  * @since 1.0.0
	  * @see  
	  */
		public static int[] Key() throws IOException{
			FileReader in = null;
			 String keystring="";
		    try {
		       in = new FileReader("key.txt");
		       
		       int c;
		      
		       while ((c = in.read()) != -1) {
		    	   keystring += new Character((char) c).toString();
		
		       }
		       
		    }finally {
		       if (in != null) {
		          in.close();
		       }
		    }
		    
		    if(keystring.length()<8){
		    	int differebce = 8 - keystring.length();
		    	for(int ik=0;ik<differebce;ik++){
		    		keystring +=" ";
		    	}
		    }
		    
		    int keyBits[] = new int[64];
		    
		    for(int i=0 ; i < 8 ; i++) {
		    	int keyint = keystring.charAt(i);    	
				String k = Integer.toBinaryString(keyint);
				while(k.length() < 8) {
					k = "0" + k;
				}
				for(int j=0 ; j < 8 ; j++) {
					keyBits[(8*i)+j] = Integer.parseInt(k.charAt(j) + "");
				}
			}
		    return keyBits;
		          
		}


		/**
		  * subkey store key in storekey variable for every round od des
		  *
		  * @author Ali Saheb
		  * @param int round           	  		  
		  * @return void
		  * @since 1.0.0
		  * @see  
		  */
	public static void subkey(int round){
		
				int C1[] = new int[28];
				int D1[] = new int[28];
						
				int rotationTimes = (int) rotations[round];
				
				C1 = leftShift(C, rotationTimes);
				D1 = leftShift(D, rotationTimes);
				
				int CnDn[] = new int[56];
				System.arraycopy(C1, 0, CnDn, 0, 28);
				System.arraycopy(D1, 0, CnDn, 28, 28);
				
				int Kn[] = new int[48];
				for(int i=0 ; i < Kn.length ; i++) {
					Kn[i] = CnDn[PC2[i]-1];
				}
							
				keyStore[round] = Kn;
				C = C1;
				D = D1;
							
	}

	/**
	  * leftShift shift key bit for every round of DES according to the round table
	  *
	  * @author Ali Saheb
	  * @param int[] bits
	  * @param int[] n           	  		  
	  * @return void
	  * @since 1.0.0
	  * @see  
	  */	
	private static int[] leftShift(int[] bits, int n) {
		
		int answer[] = new int[bits.length];
		System.arraycopy(bits, 0, answer, 0, bits.length);
		for(int i=0 ; i < n ; i++) {
			int temp = answer[0];
			for(int j=0 ; j < bits.length-1 ; j++) {
				answer[j] = answer[j+1];
			}
			answer[bits.length-1] = temp;
		}
		return answer;
	}
	/**
	  * readInputFromFile read the input.txt and return the text string
	  *
	  * @author Ali Saheb          	  		  
	  * @return String 
	  * @since 1.0.0
	  * @see  
	  */	
	public static String readInputFromFile() throws IOException{
		FileReader input = null;
		 String inputString="";
	   try {
		   input = new FileReader("input.txt");
	      
	      int inputInt;
	     
	      while ((inputInt = input.read()) != -1) {
	    	  inputString += new Character((char) inputInt).toString();
	
	      }
	      
	   }finally {
	      if (input != null) {
	    	  input.close();
	      }
	   }
	   
	   
	   return inputString;
		
	}
	/**
	  * finalResulrEnc encrypt the whole file and return the encrypted bit stream. 
	  *
	  * @author Ali Saheb          	  		  
	  * @return int[] recodrs of integer array 
	  * @since 1.0.0
	  * @see  
	  */
	public static int[] finalResulrEnc() throws IOException{
		String plainTesxt = readInputFromFile();
		int totalInputLength = plainTesxt.length();
		if(totalInputLength<8){
			for(int jk = 0;jk< 8-totalInputLength;jk++){
				plainTesxt += " ";
			}
		}
		
		if(totalInputLength%8 != 0){
			int block = totalInputLength%8;
			int addingBlock = 8-block;
			for(int blocks =0 ;blocks < addingBlock;blocks++){
				plainTesxt += " ";
			}	
		}
		
		int outputBits[] = new int[plainTesxt.length()*8];
		int limit = 0;
		int limitArr = 0;
		
		for(int roundBlock = 0;roundBlock<plainTesxt.length()/8;roundBlock++){
			int [] destArr = new int[64];
			int [] sourceArr = new int[64];
			char [] charInput =  plainTesxt.toCharArray();
			String dividedString = "";
			
			dividedString = dividedString.copyValueOf( charInput, limit, 8 );
			
			limit +=8;
			
			sourceArr = createBlock(dividedString);
			destArr = encriptFiestel(sourceArr);
			System.arraycopy(destArr, 0, outputBits, limitArr, 64);
			limitArr +=64;
			
			
		}
		
		
		   //outputBits = encriptFiestel(inputBits);
		   return outputBits;
		
	}

	/**
	  * This function accept the string of plain text and return 64 bit bit stream  
	  *
	  * @author Ali Saheb
	  * @param String  plainTesxt         	  		  
	  * @return int[] recodrs of integer array 
	  * @since 1.0.0
	  * @see  
	  */
	public static int[] createBlock(String plainTesxt){
		int inputBits[] = new int[64];
		
		   for(int i=0 ; i < 8 ; i++) {
		   	int keyint = plainTesxt.charAt(i);    	
				String k = Integer.toBinaryString(keyint);
				while(k.length() < 8) {
					k = "0" + k;
				}
				for(int j=0 ; j < 8 ; j++) {
					inputBits[(8*i)+j] = Integer.parseInt(k.charAt(j) + "");
				}
			}
		   return inputBits;
	}
	/**
	  * encriptFiestel input plain text 64 bit data then it return encrypted 64 data.   
	  *
	  * @author Ali Saheb
	  * @param String  plainTesxt         	  		  
	  * @return int[] recodrs of integer array 
	  * @since 1.0.0
	  * @see  
	  */
public static int[] encriptFiestel(int[] plainBit) throws IOException{
	int [] fistele = new int[64];
	int [] afterFP = new int[64];
	
	int [] plainText = new int[64];
	//get plaintext
	plainText = plainBit;
	
	/*Initial permutation */
	int afterIP[] = new int[plainText.length];
	for(int i=0 ; i < plainText.length ; i++) {
		afterIP[i] = plainText[IP[i]-1];
	}
	
	int L[] = new int[32];
	int R[] = new int[32];
	
	int newsR[] = new int[32];
	
	System.arraycopy(afterIP, 0, L, 0, 32);
	System.arraycopy(afterIP, 32, R, 0, 32);
	
	//ready to encript
	for(int enRound = 0;enRound<16;enRound++){
		newsR = functionBox(R,enRound);
		
		int newL[] = xor(L, newsR);
		L = R;
		R = newL;
		
	}
	System.arraycopy(R, 0, fistele, 0, 32);
	System.arraycopy(L, 0, fistele, 32, 32);
	
	for(int i=0 ; i < 64 ; i++) {
		afterFP[i] = fistele[FP[i]-1];
	}
	return afterFP;
}

/**
 * functionBox input as 32 bit data and then return the 48 bit data.  
 *
 * @author Ali Saheb
 * @param int[] R
 * @param int round         	  		  
 * @return int[] recodrs of integer array 
 * @since 1.0.0
 * @see  
 */
public static int[] functionBox(int[] R,int round){	
	int[] eBoxReturn = new int[48];
	int[] afterXor = new int[48];
	int[] afterSboxPbox = new int[32];
	/*E box*/
	for(int i=0 ; i < 48 ; i++) {
		eBoxReturn[i] = R[E[i]-1];
	}
	
	afterXor = xor(eBoxReturn,keyStore[round]);
	
	afterSboxPbox = sboxOut(afterXor);
	
	return afterSboxPbox;
	
}

/**
 * sboxOut input as 48 bit data and then return the 32 bit data.  
 *
 * @author Ali Saheb
 * @param int[] bits         	  		  
 * @return int[] recodrs of integer array 
 * @since 1.0.0
 * @see  
 */
private static int[] sboxOut(int[] bits) {
	
	int output[] = new int[32];
	
	for(int i=0 ; i < 8 ; i++) {
		int row[] = new int [2];
		row[0] = bits[6*i];
		row[1] = bits[(6*i)+5];
		String sRow = row[0] + "" + row[1];
		
		int column[] = new int[4];
		column[0] = bits[(6*i)+1];
		column[1] = bits[(6*i)+2];
		column[2] = bits[(6*i)+3];
		column[3] = bits[(6*i)+4];
		String sColumn = column[0] +""+ column[1] +""+ column[2] +""+ column[3];
		
		int iRow = Integer.parseInt(sRow, 2);
		int iColumn = Integer.parseInt(sColumn, 2);
		int x = S[i][(iRow*16) + iColumn];
		
		
		String s = Integer.toBinaryString(x);
		
		while(s.length() < 4) {
			s = "0" + s;
		}
		
		for(int j=0 ; j < 4 ; j++) {
			output[(i*4) + j] = Integer.parseInt(s.charAt(j) + "");
		}
	}
	
	int finalOutput[] = new int[32];
	for(int i=0 ; i < 32 ; i++) {
		finalOutput[i] = output[P[i]-1];
	}
	return finalOutput;
}
/**
 * xor input as a two bit stream and then xor the two bit stream and return  
 *
 * @author Ali Saheb
 * @param int[] a
 * @param int[] b        	  		  
 * @return int[] recodrs of integer array 
 * @since 1.0.0
 * @see  
 */
private static int[] xor(int[] a, int[] b) {
	// Simple xor function on two int arrays
	int answer[] = new int[a.length];
	for(int i=0 ; i < a.length ; i++) {
		answer[i] = a[i]^b[i];
	}
	return answer;
}

/**
 * printfunc write the encrypted data into the output file and print into the console.    
 *
 * @author Ali Saheb
 * @param int[] finalOutput        	  		  
 * @return void 
 * @since 1.0.0
 * @see  
 */
public static void printfunc(int[] finalOutput) throws IOException{
	int iteration=0;
	
	String beatstream = "";
	String finalOut ="";
	
	for(int i=0;i<finalOutput.length;i++){
		iteration++;
		
		beatstream += finalOutput[i];
		if(iteration == 4){
			iteration=0;
			int anciiCode = Integer.parseInt(beatstream, 2);
			finalOut += Integer.toString(anciiCode,16);
			//finalOut +=Character.toString ((char) anciiCode); 
			beatstream="";
		}
		
	}
	
	
    FileOutputStream out = null;

    try {
       
       out = new FileOutputStream("output.txt");
       //finalOut;
       for(int ij =0;ij<finalOut.length();ij++){
    	   int chars;
    	   chars= finalOut.charAt(ij);
    	   out.write(chars);  
    	   }
          
    }finally {
       
       if (out != null) {
          out.close();
       }
	
	System.out.println(finalOut);
	
}
}

/**
 * readOutputFromFile read the output.txt and return the string of the output.txt.    
 *
 * @author Ali Saheb        	  		  
 * @return String 
 * @since 1.0.0
 * @see  
 */

public static String readOutputFromFile() throws IOException{
	FileReader input = null;
	 String inputString="";
   try {
	   input = new FileReader("output.txt");
      
      int inputInt;
     
      while ((inputInt = input.read()) != -1) {
    	  inputString += new Character((char) inputInt).toString();

      }
      
   }finally {
      if (input != null) {
    	  input.close();
      }
   }
   
   System.out.println(inputString);
   return inputString;
	
}

/**
 * finalDecription decrypt the encrypted text    
 *
 * @author Ali Saheb        	  		  
 * @return void 
 * @since 1.0.0
 * @see  
 */
public static void finalDecription() throws IOException{
	
	String ciperText = readOutputFromFile();
	int totalInputLength = ciperText.length();
	int limit =0;
	int limitArr =0;
	int [] outputBits = new int[totalInputLength*4];
	for(int i=0;i<totalInputLength/16;i++){
		
		int [] destArr = new int[64];
		int [] sourceArr = new int[64];
		
		char [] charInput =  ciperText.toCharArray();
		String dividedString = "";
		
		dividedString = dividedString.copyValueOf( charInput, limit, 16 );
		
		limit +=16;
		
		sourceArr = createCiperBlock(dividedString);
		
		
		destArr = decrypeFistal(sourceArr);
		System.arraycopy(destArr, 0, outputBits, limitArr, 64);
		limitArr +=64;
		
	}
	printfuncDEC(outputBits);
	
		
}

/**
 * createCiperBlock create 64 bit block from hexadecimal input    
 *
 * @author Ali Saheb
 * @param String input        	  		  
 * @return int[] record of data 
 * @since 1.0.0
 * @see  
 */
public static int[] createCiperBlock(String input){
	int cyperBits[] = new int[64];
	for(int i=0 ; i < 16 ; i++) {
		String s = Integer.toBinaryString(Integer.parseInt(input.charAt(i) + "", 16));
		while(s.length() < 4) {
			s = "0" + s;
		}
		for(int j=0 ; j < 4 ; j++) {
			cyperBits[(4*i)+j] = Integer.parseInt(s.charAt(j) + "");
		}
	}
	return cyperBits;
}

/**
 * decrypeFistal decrypt the 64 bit block of data    
 *
 * @author Ali Saheb
 * @param int[] plainBit         	  		  
 * @return int[] record of data 
 * @since 1.0.0
 * @see  
 */
public static int[] decrypeFistal(int [] plainBit){
	int [] fistele = new int[64];
	int [] afterFP = new int[64];
	
	int [] plainText = new int[64];
	//get plaintext
	plainText = plainBit;
	
	/*Initial permutation */
	int afterIP[] = new int[plainText.length];
	for(int i=0 ; i < plainText.length ; i++) {
		afterIP[i] = plainText[IP[i]-1];
	}
	
	int L[] = new int[32];
	int R[] = new int[32];
	
	int newsR[] = new int[32];
	
	System.arraycopy(afterIP, 0, L, 0, 32);
	System.arraycopy(afterIP, 32, R, 0, 32);
	
	//ready to encript
	for(int enRound = 0;enRound<16;enRound++){
		newsR = functionBox(R,15-enRound);
		
		int newL[] = xor(L, newsR);
		L = R;
		R = newL;
		
	}
	System.arraycopy(R, 0, fistele, 0, 32);
	System.arraycopy(L, 0, fistele, 32, 32);
	
	for(int i=0 ; i < 64 ; i++) {
		afterFP[i] = fistele[FP[i]-1];
	}
	return afterFP;
}

/**
 * printfuncDEC write in the gen_output.txt after decryption .    
 *
 * @author Ali Saheb
 * @param int[] finalOutput         	  		  
 * @return void 
 * @since 1.0.0
 * @see  
 */
public static void printfuncDEC(int[] finalOutput) throws IOException{
	int iteration=0;
	
	String beatstream = "";
	String finalOut ="";
	
	for(int i=0;i<finalOutput.length;i++){
		iteration++;
		
		beatstream += finalOutput[i];
		if(iteration == 8){
			iteration=0;
			int anciiCode = Integer.parseInt(beatstream, 2);
			//finalOut += Integer.toString(anciiCode,16);
			finalOut +=Character.toString ((char) anciiCode); 
			beatstream="";
		}
		
	}
	
	
    FileOutputStream out = null;

    try {
       
       out = new FileOutputStream("gen_input.txt");
       //finalOut;
       for(int ij =0;ij<finalOut.length();ij++){
    	   int chars;
    	   chars= finalOut.charAt(ij);
    	   out.write(chars);  
    	   }
          
    }finally {
       
       if (out != null) {
          out.close();
       }
	
	System.out.println(finalOut);	
 }
}

}


