package encryptionAlgorithms.AES;

import java.util.Random;

public class AESEncrypter {
	
	//////////////////////////////////
	// Initialisation and Variables //
	//////////////////////////////////
	
	
	// Static variables.
	static int numRounds = 0;
	static int [][] expandedkey;
	static int [][] plainText;
	static boolean verbose = false;
	
	 // Constructor.
	 public AESEncrypter(String plaintext, int keySize, int[][] key, boolean v, boolean padWithZeroes)
	 {
		 // Declare variables.
		 final int Nk = 4;
		 String[] plainTempArray = plaintext.split("(?!^)");
		 
		 
		 // Initialise static variables.
		 verbose = v;
		 plainText = new int[4][4];
		 expandedkey = AESEncrypter.ExpandKey(Nk, key);
		 plainText = generatePlainTextBytes(plainTempArray, Nk, padWithZeroes);

		 // Decide on number of rounds given key size (this allows for possible expansion of the algorithm for larger keys).
		 switch(keySize)
		 {
		 	case 128: numRounds = 10;
		 	break;
		 	case 192: numRounds = 12;
		 	break;
		 	case 256: numRounds = 14;
		 }
	 };
	
	 // Standard S-Box.
	 static final char[][] SBox = 
	{ 
		 {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, 
		 {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, 
		 {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, 
		 {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, 
		 {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, 
		 {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, 
		 {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, 
		 {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, 
		 {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, 
		 {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, 
		 {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, 
		 {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, 
		 {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, 
		 {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, 
		 {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, 
		 {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} 
	};

	 
	 // Key for this assignment.
	 static final int [][] key = 
	{
		 {0xa0, 0x88, 0x23, 0x2a}, 
		 {0xfa, 0x54, 0xa3, 0x6c}, 
		 {0xfe, 0x2c, 0x39, 0x76}, 
		 {0x17, 0xb1, 0x39, 0x05}
	};
			 
	
	 // Test Key from the module notes.
	 static final int[][] key1 = 
	{
		 {0x2b, 0x28, 0xab, 0x09}, 
		 {0x7e, 0xae, 0xf7, 0xcf}, 
		 {0x15, 0xd2, 0x15, 0x4f}, 
		 {0x16, 0xa6, 0x88, 0x3c}
	};
	 
	 // Test plain text from the module notes.
	 static int [][] plainTest = 
	{
		 {0x32, 0x88, 0x31, 0xe0},
		 {0x43, 0x5a, 0x31, 0x37},
		 {0xf6, 0x30, 0x98, 0x07},
		 {0xa8, 0x8d, 0xa2, 0x34}
		 
    };
 
	 // Pre-calculated RCon values for key expansion.
	 static int [] RCon = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
	 
	 // Table for mix columns step of AES.
	 static int [][] mixColsTable = 
	 {
		 {2, 3, 1, 1},
		 {1, 2, 3, 1},
		 {1, 1, 2, 3},
		 {3, 1, 1, 2}
		 
	 };

	 
	 
	 ///////////////////
	 // AES Methods.  //
	 ///////////////////
	 
	 // The Substitute Bytes method.
	 static int[][] SubBytes(int [][] state)
	 {
		 byte temp;
		 for(int i = 0; i < state.length; i++)
			 for(int j = 0; j < state[i].length; j++)
			 {
				 temp = (byte) state[i][j];
				 state[i][j] = (byte) SBox[getFirstNumInByte(temp)][getSecondNumInByte(temp)];
			 }
		 return state;
	 }
	 
	 
	 // The Shift Rows method.
	 static int[][] ShiftRows(int [][] state)
	 {
		int offset = 1;
		int onset = state.length - 1;
		int modj = 0;
		int [] temp = new int[state.length];
		 
		// Begin from the second row.
		for(int i = 1; i < state.length; i++)
		{
			 for(int j = 0; j < state[i].length; j++)
			 {
				 modj = j%4;
				 if(modj < offset)
					 temp[(modj + onset)] = state[i][j];
				 else
					 temp[(modj - offset)] = state[i][j];
			 }
			 
			 for(int x = 0; x < state[i].length; x++)
				 state[i][x] = temp[x];
			 
			 offset++;
			 onset--;
		}
		
		return state; 
	 }

	 
	 // The Mix Columns method.
	 static int[][] MixColumns(int [][] state)
	 {
		 int []tempState = new int[4];
		 int [][] mixedState = new int [4][4];
	
		 for(int x = 0; x < state.length; x++)
		 {	
			 for(int i = 0; i < state.length; i++)			 
			 {	
			 		for(int j = 0; j < state[i].length; j++)
			 		{ 
			 			int nextResult = mixColsHelper((state[j][x] &= (0xff)), AESEncrypter.mixColsTable[i][j], false);
			 			tempState[j] = nextResult;
			 		}
				 	 
			 		mixedState[i][x] = (((tempState[0] ^ tempState[1]) ^ tempState[2]) ^ tempState[3]);	 
			 }
		 }
		 
		return mixedState;
	 }
	 
	 
	 // The Add Round Key method.
	 static int[][] AddRoundKey(int [][] state, int[][] tempkey)
	 {
		 for(int i = 0; i < state.length; i++)
			 for(int j = 0; j < state[i].length; j++)
			 { 
				 state[j][i] = state[j][i] ^ tempkey[j][i];
			 }

		 return state;
	 }
	 


	 
	 
	 
	 ///////////////////////////////////////////////////////
	 // Auxiliary Functions.							  //
	 ///////////////////////////////////////////////////////
	 
	 // Gets the first digit in a byte.
	 public static byte getFirstNumInByte(byte b)
	 {
		 byte upper = (byte) ((b >> 4) & 0xF);
		 return upper;
	 }
	 
	 // Gets the second digit in a byte.
	 public static byte getSecondNumInByte(byte b)
	 {
		 byte lower = (byte) (b & 0xF);
		 return lower;
	 }
	 
	 // Shifts left and returns an 8-bit byte.
	 private static int shiftLeft(int s)
	 {
		 s <<= 1;
		 return(s &= (0xff)); 
	 }
	 
	 // Pads the plain text with random bytes.
	 int [][] generatePlainTextBytes(String[] plainTempArray, int Nk, boolean padWithZeroes)
	 {
		 int c = 0;
		 int max= 255;
		 int min = 0;
		 Random rand = new Random();
		 int [][] plainText = new int[4][Nk];
		 
		 // Block size will be 4 32-bit (4 byte) words.
		 for(int i = 0; i < Nk; i++)
			 for(int j = 0; j < 4; j++)
			 {
				 if(c > plainTempArray.length-1)
				 {
					 // Generate a random padding byte.
					 if(padWithZeroes == false)
						 plainText[j][i] =  (byte) rand.nextInt((max - min) + 1) + min;
					 else
						 plainText[j][i] = (byte) 00;
				 }
				 else
				 {
					 plainText[j][i] = Integer.parseInt(String.format("%04x", (int)plainTempArray[c].charAt(0)));
					 c++;
				 } 
			 }
		 
		 printValues(plainText);
		 return plainText;
	 }
	 
	 // Helps with the multiplication within the Mix Columns method.
	 private static int mixColsHelper(int stateNum, int multiplier, boolean flag)
	 {
         stateNum &= (0xff);
		 String binString = Integer.toBinaryString(stateNum);
		 
		 switch(multiplier)
		 {
		 	case 1: return stateNum; 
		 	
		 	case 2: 
		 	{
		 		stateNum = shiftLeft(stateNum);
		 		
		 		// If there is a zero at the beginning of the number.
		 		if(binString.length() < 8)
		 			return stateNum;
		 		else
		 			stateNum ^= 27;
		
		 		return stateNum;
		 	}
		 	
		 	case 3: return (stateNum ^ mixColsHelper(stateNum, 2, true));		
		 }
		
		// If error.
		return 0;
	 }
	 
	 // Key Expansion.
	 public static int[][] ExpandKey(int Nk, int [][] key)
	 {
		 // Initialisation.
		 int[][] expandedKey = new int[Nk][44];
		 int ival = Nk;
		 int Rcon = RCon[0];
		 int [] workingArray = new int[4];
		 
		 for(int i = 0; i < key.length; i++)
			 for(int j = 0; j < key.length; j++)
			 {
				 expandedKey[j][i] = key[j][i];
				 
				 if(i == Nk-1)
					 workingArray[j] = key[j][i];
			 }
		
		 for(int i = 0; i < 40; i++)
		 {
			 if((ival)%4 ==0)
			 {
				 workingArray = rotWord(workingArray);
				 workingArray = subWord(workingArray);
				 Rcon = (RCon[((ival)/Nk)-1]);
				 workingArray[0] ^= (Rcon);
			   
				 for(int j = 0; j < workingArray.length; j++)
				 {
					 workingArray[j] ^= expandedKey[j][ival-Nk];
					 expandedKey[j][ival] = workingArray[j];
				 }
			 }
			 else
			 {
				 for(int j = 0; j < workingArray.length; j++)
				 {
					 workingArray[j] ^= expandedKey[j][ival-Nk];
					 expandedKey[j][ival] = workingArray[j];
				 }
			 }
	   
			 ival++;
		 }

		 return expandedKey; 
	 }
	 
	 // SubWord method used in Key Expansion.
	 static int[] subWord(int [] temp)
	 {
		 for(int i = 0; i < temp.length; i++)
			 temp[i] = (byte) SBox[getFirstNumInByte((byte) temp[i])][getSecondNumInByte((byte) temp[i])];

		return temp; 
	 }
	 
	 // Rotate Word method used in Key Expansion.
	 static int [] rotWord(int [] key)
	 {
		 int offset = 1;
	     int onset = key.length - 1;
	     int [] temp = new int[4];
	     
	     for(int j = 0; j < key.length; j++)
		 {
			 int modj = j%4;
			 if(modj < offset)
				 temp[(modj + onset)] = key[j];
			 else
				 temp[(modj - offset)] = key[j]; 
		 }
     
		return temp; 
	 }
	 
	 // Gets the key for the current round.
	 static int [][] getRoundKey(int round, int [][] tempkey)
	 {   
		 if(verbose)
			 System.out.print("key: ");
		 
		 for(int i = 0; i < tempkey.length; i++)
			 for(int j = 0; j < tempkey[i].length; j++)
			 {
				 tempkey[j][i] = expandedkey[j][i + (4 * round)];
				 
				 if(verbose)
					 System.out.print((Integer.toHexString((tempkey[j][i] &= 0xff)) + " "));
			 }
		 
		 return tempkey;
	 }
	 
	 /////////////////////////////////////////////////////////////////////////////////////////////////////
	 // Main Method.                                                                   ///////
	 /////////////////////////////////////////////////////////////////////////////////////////////////////
	
	 public static void main(String args[])
	 {
		 // These variables can be changed according to preference.
		 // Verbose specifies whether output should be printed.
		 // PadWithZeroes specifies whether the plaintext should be padded with random bytes or 0's.
		 String plaint = "test";
		 boolean verbose = true;
		 boolean padWithZeroes = false;
		 
		 /* TO TEST THE ALGORITHM WITH THE VALUES FROM THE 
		  * LECTURE NOTES, UNCOMMENT THESE 4 LINES AND COMMENT
		  * OUT THE 2 LINES BELOW THESE.
		  
		 AESEncrypter.verbose = true;
		 AESEncrypter.numRounds = 10;
		 int[][] state = plainTest; 
		 expandedkey = AESEncrypter.ExpandKey(4, key1); */

		AESEncrypter aes = new AESEncrypter(plaint, 128, AESEncrypter.key, verbose, padWithZeroes);
		int[][] state = AESEncrypter.plainText;
		
		
		int[][] key = new int [4][4];
		state = AddRoundKey(state, getRoundKey(0, key));
		 
		 if(AESEncrypter.verbose)
		 {
			 System.out.println("\n\nStart State: ");
			 printValues(state);
		 }
		 
		 for(int i = 0; i < AESEncrypter.numRounds; i++)
		 {
			 // Get key for this round and store it locally.
			 key = getRoundKey(i+1, key);
			 
			 // Perform round of AES.
			 if(i+1 == 10)
			 {
				 state = AESEncrypter.SubBytes(state);
				 state = AESEncrypter.ShiftRows(state);
				 state = AESEncrypter.AddRoundKey(state, key);
			 }
			 else
			 {
				 state = AESEncrypter.SubBytes(state);
				 state = AESEncrypter.ShiftRows(state);
				 state = AESEncrypter.MixColumns(state);
				 state = AESEncrypter.AddRoundKey(state, key);
			 }
			 
			 if(AESEncrypter.verbose)
			 {
				 System.out.println("\n\nState after round "  + (i+1) + ": ");
				 printValues(state);
			 }
		 }
	 }
	 


	 ///////////////////
	 //Informal Tests //	
	 ///////////////////

	 public static void printValues(int [][] state)
	 {
		 for(int i = 0; i < state.length; i++)
			 for(int j = 0; j < state[i].length; j++)
			 { 			
				 System.out.print(Integer.toHexString((state[i][j] &= (0xff))) + " ");
		
				 if((j+1)%4==0)
					 System.out.print("\n");
			 }
		 
		 System.out.println();
	 }
	 
	 public static void printColumns(int [][] state)
	 {
		 System.out.println();
		 
		 for(int i = 0; i < state.length; i++)
			 for(int j = 0; j < 4; j++)
			 { 			
				 System.out.print(Integer.toHexString((state[j][i] &= (0xff))) + " " );
		
				 if((j+1)%4==0)
					 System.out.print("\n");
			 }
	 }
	 
	 public static void printBytes(int [][] bytes)
	 {
		 System.out.println();
		 
		 for(int i = 0; i < bytes.length; i++)
			 for(int j = 0; j < bytes[i].length; j++)
			 {
				 System.out.println(bytes[i][j] + " ");
					
				 if((j+1)%bytes[i].length==0)
					 System.out.print("\n");
			 }
	 }

}





