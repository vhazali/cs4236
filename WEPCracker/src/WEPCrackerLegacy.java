//
//import java.io.FileInputStream;
//import java.io.FileNotFoundException;
//import java.io.IOException;
//import java.io.InputStream;
//import java.util.Arrays;
//import java.util.HashMap;
//import java.util.Map;
//
///**
// * Main class of the cracker.
// * It will read in a data file, and attempt to guess the key for the RC4
// * encrypted data.
// * Class is called by supplying 1 variable, which is the file name containing
// * the RC4 encrypted data.
// * 
// * @author Victor Hazali
// */
//public class WEPCrackerLegacy {
//
//	private static final int	MAX_KEY_VAL			= 90;
//	public static final int		IV_KNOWN_SIZE		= 3;
//	public static final int		KEY_BYTE_SIZE		= 4;
//	public static final int		TUPLE_NUM_BYTE_SIZE	= 4;
//	public static final int		TUPLE_BYTE_SIZE		= IV_KNOWN_SIZE + 1;
//	public static final boolean	DEBUG_MODE			= true;
//	public static final int		EXIT_WITH_ERROR		= 1;
//	private static final int	INIT				= 0;
//	private static final int	INIT_KEY			= -1;
//	// number of bytes of keys. given in question as 160 instead of 256
//	public static final int		KEY_SPACE			= 160;
//	private static final double	THRESHOLD			= 0.9;
//	private static final String	STUB				= "This is a stub message. This function is still under development.\n";
//	private static final String	FILE_NOT_FOUND		= "File cannot be found.\n";
//	private static final String	INVALID_INVOCATION	= "Please supply at least 1 filename while activating the program as such: java WEPCracker <filename>.\n";
//	private static final String	NO_RESULT			= "Could not evaluate result.";
//	private static final String	FAIL_READ_LENGTH	= "Failed to read key length from file.\n";
//	private static final String	FAIL_READ_TUPLE_NUM	= "Failed to read number of tuples in file.\n";
//	private static final String	FAIL_READ_TUPLE		= "Failed to read tuple.\n";
//	private static final String	FAIL_CLOSE_READER	= "Failed to close _fileReader.\n";
//
//	private InputStream			_fileReader;
//	private String				_fileName;
//	private String				_result;
//	private int					_keyLength;
//	private int					_numOfTuples;
//	private Tuple				_tuple;
//	private int[]				_frequency;
//	private Map<String, Tuple>	_tuples;
//	private int					_latestKey;
//	private int					_knownKeyLength;
//
//	/* Constructors */
//	public WEPCrackerLegacy() {
//	}
//
//	/* Acessors and Modifiers */
//	public String getFileName() {
//		return _fileName;
//	}
//
//	public void setFileName(String fileName) {
//		_fileName = fileName;
//	}
//
//	public String getResult() {
//		return _result;
//	}
//
//	public void setResult(String result) {
//		_result = result;
//	}
//
//	public int getKeyLength() {
//		return _keyLength;
//	}
//
//	public void setKeyLength(int keyLength) {
//		_keyLength = keyLength;
//	}
//
//	public int getNumOfTuples() {
//		return _numOfTuples;
//	}
//
//	public void setNumOfTuples(int numOfTuples) {
//		_numOfTuples = numOfTuples;
//	}
//
//	public Tuple getWorkingTuple() {
//		return _tuple;
//	}
//
//	public void setWorkingTuple(Tuple tuple) {
//		_tuple = tuple;
//	}
//
//	public int[] getFrequency() {
//		return _frequency;
//	}
//
//	public int getFrequencyIndex(int index) {
//		return _frequency[index];
//	}
//
//	public void setFrequency(int[] frequencyTable) {
//		_frequency = frequencyTable;
//	}
//
//	public void setFrequency(int index, int value) {
//		_frequency[index] = value;
//	}
//
//	// Increment the frequency of the index by 1
//	public void incrementFrequency(int index) {
//		_frequency[index]++;
//	}
//
//	public Map<String, Tuple> getTuples() {
//		return _tuples;
//	}
//
//	public Tuple getTupleFromMap(String id) {
//		return _tuples.get(id);
//	}
//
//	public void setTuples(Map<String, Tuple> tuples) {
//		_tuples = tuples;
//	}
//
//	public void addTupleToMap(Tuple value) {
//		_tuples.put(value.getIdentifier(), value);
//	}
//
//	public int getLatestKey() {
//		return _latestKey;
//	}
//
//	public void setLatestKey(int latestKey) {
//		_latestKey = latestKey;
//	}
//
//	public int getKnownKeyLength() {
//		return _knownKeyLength;
//	}
//
//	public void resetKnownKeyLength() {
//		_knownKeyLength = IV_KNOWN_SIZE;
//	}
//
//	public void incrementKnownKeyLength() {
//		_knownKeyLength++;
//	}
//
//	/* Private methods */
//	/**
//	 * Initializes all member variables for current working file.
//	 * Sets the filename as specified by user
//	 * Sets _fileReader to read from the file specified by user
//	 * Sets result to the init value NO_RESULT
//	 * Sets both key length and number of tuples to init value INIT
//	 * Sets the working tuple to null
//	 * Create a new frequency table with MAX_KEY_VAL number of elements
//	 * Create a new HashMap with key String and valeu Tuple
//	 * Set latest key to INIT_KEY
//	 * Create a new key array with length INIT
//	 * 
//	 * @param filename
//	 */
//	private void initialise(String filename) {
//		setFileName(filename);
//		try {
//			_fileReader = new FileInputStream(filename);
//		} catch (FileNotFoundException e) {
//			if (DEBUG_MODE) {
//				showToUser(FILE_NOT_FOUND);
//				this.toString();
//				e.printStackTrace();
//			}
//			System.exit(EXIT_WITH_ERROR);
//		}
//		setResult(NO_RESULT);
//		setKeyLength(INIT);
//		setNumOfTuples(INIT);
//		setWorkingTuple(null);
//		setFrequency(new int[MAX_KEY_VAL]);
//		setTuples(new HashMap<String, Tuple>());
//		setLatestKey(INIT_KEY);
//		resetKnownKeyLength();
//	}
//
//	/**
//	 * Method to read the key length for the set of data.
//	 * Key length is specified at the first KEY_BYTE_SIZE bytes in file.
//	 * 
//	 * @return length of key for working set of data
//	 */
//	private int readKeyLength() {
//		byte[] bytes = new byte[KEY_BYTE_SIZE];
//		try {
//			_fileReader.read(bytes);
//		} catch (IOException e) {
//			if (DEBUG_MODE) {
//				showToUser(FAIL_READ_LENGTH);
//				this.toString();
//				e.printStackTrace();
//			}
//			System.exit(EXIT_WITH_ERROR);
//		}
//		return java.nio.ByteBuffer.wrap(bytes)
//				.order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
//	}
//
//	/**
//	 * Method to read the number of tuples that will be in the set of data.
//	 * Number of tuples is specified as the next TUPLE_NUM_BYTE_SIZE bytes in
//	 * file.
//	 * 
//	 * @return number of tuples to work with in the working set of data.
//	 */
//	private int readNumOfTuples() {
//		byte[] bytes = new byte[TUPLE_NUM_BYTE_SIZE];
//		try {
//			_fileReader.read(bytes);
//		} catch (IOException e) {
//			if (DEBUG_MODE) {
//				showToUser(FAIL_READ_TUPLE_NUM);
//				this.toString();
//				e.printStackTrace();
//			}
//			System.exit(EXIT_WITH_ERROR);
//		}
//		return java.nio.ByteBuffer.wrap(bytes)
//				.order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
//	}
//
//	/**
//	 * Reads all the tuples from the data file and then store them
//	 * all into the array _tuples
//	 */
//	private void readTuples() {
//		byte[] bytes = new byte[TUPLE_BYTE_SIZE];
//
//		for (int i = 0; i < getNumOfTuples(); i++) {
//			try {
//				_fileReader.read(bytes);
//			} catch (IOException e) {
//				if (DEBUG_MODE) {
//					showToUser(FAIL_READ_TUPLE);
//					this.toString();
//					e.printStackTrace();
//				}
//				System.exit(EXIT_WITH_ERROR);
//			}
//			addTupleToMap(new Tuple(bytes, getKeyLength()));
//		}
//	}
//
//	/**
//	 * Runs the KSA algorithm on the tuple to determine if the key used is weak.
//	 * If it is, the algorithm will return the candidate.
//	 * This method then updates the frequency table.
//	 */
//	private void addKeyCandidate() {
//		int candidate = RC4Modified.KSA(getWorkingTuple());
//		if (isValidCandidate(candidate)) {
//			incrementFrequency(candidate);
//		}
//	}
//
//	private boolean isValidCandidate(int candidate) {
//		return candidate < MAX_KEY_VAL && candidate >= 0;
//	}
//
//	private void guessKey() {
//		// Repeat for number of unknown bytes of key
//		for (int i = IV_KNOWN_SIZE; i < getKeyLength(); i++) {
//			// reset frequency table
//			setFrequency(new int[MAX_KEY_VAL]);
//			// Repeat for all tuples
//			for (Tuple tuple : getTuples().values()) {
//				if (i != IV_KNOWN_SIZE) {
//					// Not first pass, so need to increment known key length,
//					// and add latest key byte
//					tuple.setIVIndex(tuple.getKnownKeyLength(), getLatestKey());
//					tuple.incrementKnownKeyLength();
//				}
//				setWorkingTuple(tuple);
//				addKeyCandidate();
//			}
//			// Compare all the frequencies to choose most likely key
//			// Note that key is only in the range of [0,89] hence loop till 89
//			int max = INIT, maxIndex = INIT;
//			for (int j = 0; j < 90; j++) {
//				if (getFrequencyIndex(j) > max) {
//					maxIndex = j;
//					max = getFrequencyIndex(j);
//				}
//			}
//			setLatestKey(maxIndex);
//
//		}
//
//	}
//
//	private void formatResult() {
//		StringBuilder sb = new StringBuilder();
//
//		sb.append("Filename: " + getFileName() + " Keylength: "
//				+ getKeyLength());
//		sb.append(" Key: ");
//		sb.append("\n");
//
//		setResult(sb.toString());
//	}
//
//	private void cleanup() {
//		try {
//			_fileReader.close();
//		} catch (IOException e) {
//			if (DEBUG_MODE) {
//				e.printStackTrace();
//				showToUser(FAIL_CLOSE_READER);
//			}
//		}
//	}
//
//	private boolean verifyResult() {
//		int correct = 0;
//		int wrong = 0;
//		for (Tuple tuple : getTuples().values()) {
//			int temp = RC4Modified.RC41Byte(tuple);
//			if (tuple.getOutput() != temp) {
//				wrong++;
//			} else {
//				correct++;
//			}
//		}
//
//		// DEBUG
//		System.out.println("Wrong: " + wrong);
//		System.out.println("Correct: " + correct);
//
//		double total = correct + wrong;
//		return correct / total > THRESHOLD;
//
//	}
//
//	/* Public Methods */
//	public void fmsAttack(String filename) {
//		initialise(filename);
//		setKeyLength(readKeyLength());
//		setNumOfTuples(readNumOfTuples());
//		readTuples();
//		guessKey();
//		if (DEBUG_MODE) {
//			if (verifyResult()) {
//				showToUser("Key is correct with a rate of " + THRESHOLD * 100
//						+ "%\n");
//			} else {
//				showToUser("Key failed to clear accuracy rate of " + THRESHOLD
//						* 100 + "%\n");
//			}
//		}
//		formatResult();
//	}
//
//	/**
//	 * Driver method for the WEP Cracker program.
//	 * Program will eventually display the keys for each file cracked, or a
//	 * message to show user that the file could not be cracked.
//	 * 
//	 * @param args
//	 *            contains the array of file names to crack
//	 */
//	public static void main(String[] args) {
//		if (args.length <= 0) {
//			showToUser(INVALID_INVOCATION);
//			System.exit(EXIT_WITH_ERROR);
//		}
//		WEPCrackerLegacy cracker = new WEPCrackerLegacy();
//		for (int i = 0; i < args.length; i++) {
//			cracker.fmsAttack(args[i]);
//			showToUser(cracker.getResult());
//		}
//		cracker.cleanup();
//	}
//
//	/**
//	 * This method will display a string representation of the WEP Cracker
//	 * class.
//	 * Format will be as follows:
//	 * 
//	 * <pre>
//	 * Filename: 
//	 * Result:
//	 * Key length:
//	 * Number of tuples: 
//	 * Currently working on tuple:
//	 * </pre>
//	 */
//	@Override
//	public String toString() {
//		StringBuilder sb = new StringBuilder();
//		sb.append("Filename \t\t:" + getFileName() + "\n");
//		sb.append("Result \t\t\t:" + getResult() + "\n");
//		sb.append("Key Length \t\t:" + getKeyLength() + "\n");
//		sb.append("No. of tuples \t:" + getNumOfTuples() + "\n");
//		if (DEBUG_MODE) {
//			if (getWorkingTuple() != null) {
//				sb.append("Working tuple \t:{\n" + getWorkingTuple().toString()
//						+ "}\n");
//			}
//			sb.append("Frequency \t:" + Arrays.toString(getFrequency()) + "\n");
//			sb.append("Map size\t: " + getTuples().size() + "\n");
//			sb.append("Latest key \t:" + getLatestKey() + "\n");
//		}
//		return sb.toString().trim();
//	}
//
//	/**
//	 * Method will show a message to user.
//	 * This method does no additional formatting.
//	 * Usage of the
//	 * 
//	 * @param message
//	 */
//	public static void showToUser(String message) {
//		System.out.print(message);
//	}
//
//}
//
