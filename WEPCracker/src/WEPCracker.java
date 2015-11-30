import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Program to crack WEP given datasets that contain multiple (IV,r) pairs.
 * IV:= Initial Value, r := first output byte of RC4
 * Program will try to find a key for each data set that is able to break at
 * least THRESHOLD*100 percent of (IV,r) pairs.
 * Note that program may not find any key that is 100% correct.
 * Possible improvement will be to fine tune the validateKey method to allow for
 * program to look for a key that is 100% correct
 * 
 * @author Victor Hazali
 */
public class WEPCracker {

	/* Constants */
	public static final boolean	DEBUG_MODE			= false;

	private static final int	INIT				= 0;
	public static final int		EXIT_WITH_ERROR		= 1;
	public static final int		KEY_BYTE_SIZE		= 4;
	public static final int		TUPLE_NUM_BYTE_SIZE	= 4;
	public static final int		IV_SIZE				= 3;
	public static final int		TUPLE_BYTE_SIZE		= IV_SIZE + 1;
	// the value of N in RC4 shall be named KEY_SPACE for this program
	public static final int		KEY_SPACE			= 160;
	// To define how many keys to try. Only top KEY_BOUND keys will be tested
	private static final int	KEY_BOUND			= 2;
	private static final int	KEY_INIT			= KEY_BOUND + 1;
	// Defines the upper bound of the possible key value for each byte
	private static final int	MAX_KEY_VAL			= 90;
	// Number of trailing key bytes to attempt to brute force
	// Change this value to decide how many bytes to guess using FMS
	private static final int	NUM_TO_BF			= 3;
	private static final int	THRESHOLD			= 20;

	// Exception messages
	private static final String	INVALID_INVOCATION	= "Please supply at least 1 filename while activating the program as such: java WEPCracker <filename>.\n";
	private static final String	FILE_NOT_FOUND		= "File cannot be found.\n";
	private static final String	FAIL_READ_LENGTH	= "Failed to read key length from file.\n";
	private static final String	FAIL_READ_TUPLE_NUM	= "Failed to read number of tuples in file.\n";
	private static final String	FAIL_READ_TUPLE		= "Failed to read tuple.\n";
	private static final String	FAIL_CLOSE_READER	= "Failed to close _fileReader.\n";

	/* Member Variables */
	/*
	 * When adding new member variables:
	 * add getters and setters
	 * initialise within the initialise() method
	 * add to output in toString() method
	 */
	private String				_fileName;
	private InputStream			_fileReader;
	private int[]				_key;
	private int					_numOfTuples;
	private Map<String, Tuple>	_tuples;

	/* Constructors */
	public WEPCracker() {
	}

	/* Public Methods */

	public void crack(String filename) {
		initialise();
		setFileName(filename);
		readFile();
		String result = fmsAttack();
		showResult(result);
	}

	/* Private methods */
	private void initialise() {
		setFileName("");
		setKey(new int[INIT]);
		setNumOfTuples(INIT);
		setTuples(new HashMap<String, Tuple>());
	}

	private void readFile() {
		try {
			_fileReader = new FileInputStream(getFileName());
		} catch (FileNotFoundException e) {
			if (DEBUG_MODE) {
				showToUser(FILE_NOT_FOUND);
				this.toString();
				e.printStackTrace();
			}
			System.exit(EXIT_WITH_ERROR);
		}
		readKeyLength();
		readNumOfTuples();
		readTuples();
	}

	public String fmsAttack() {
		StringBuilder sb = new StringBuilder();
		if (guessKey()) {
			sb.append("Filename: " + getFileName() + "\n");
			sb.append("Key\t: ");
			for (int i = 0; i < getKey().length; i++) {
				sb.append(getKeyAt(i) + " ");
			}
			sb.append("\n");
		} else {
			sb.append("Failed to find key for " + getFileName() + "\n");
		}

		return sb.toString();
	}

	public void showResult(String result) {
		showToUser(result);
	}

	/**
	 * Method will read the key length for the current set of data.
	 * Key length is specified at the first KEY_BYTE_SIZE bytes in the file
	 * The key length will then be stored in the variable _keyLength
	 */
	private void readKeyLength() {
		byte[] bytes = new byte[KEY_BYTE_SIZE];

		try {
			read(bytes);
		} catch (IOException e) {
			if (DEBUG_MODE) {
				showToUser(FAIL_READ_LENGTH);
				this.toString();
				e.printStackTrace();
			}
			System.exit(EXIT_WITH_ERROR);
		}
		int keyLen = (java.nio.ByteBuffer.wrap(bytes).order(
				java.nio.ByteOrder.LITTLE_ENDIAN).getInt());
		setKey(new int[keyLen - IV_SIZE]);
	}

	/**
	 * Method will read the number of tuples existing in current set of data.
	 * Number of tuples is specified as the next TUPLE_NUM_BYTE_SIZE bytes in
	 * the file.
	 * Number of tuples is then stored in the variable _numOfTuples
	 */
	private void readNumOfTuples() {
		byte[] bytes = new byte[TUPLE_NUM_BYTE_SIZE];
		try {
			read(bytes);
		} catch (IOException e) {
			if (DEBUG_MODE) {
				showToUser(FAIL_READ_TUPLE_NUM);
				this.toString();
				e.printStackTrace();
			}
			System.exit(EXIT_WITH_ERROR);
		}
		setNumOfTuples(java.nio.ByteBuffer.wrap(bytes)
				.order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt());
	}

	/**
	 * Method will read all tuples from data file and store it into a map
	 * Identifier will be specified in the tuple's getIdentifier() method
	 */
	private void readTuples() {
		byte[] bytes = new byte[TUPLE_BYTE_SIZE];

		for (int i = 0; i < getNumOfTuples(); i++) {
			try {
				read(bytes);
			} catch (IOException e) {
				if (DEBUG_MODE) {
					showToUser(FAIL_READ_TUPLE);
					this.toString();
					e.printStackTrace();
				}
				System.exit(EXIT_WITH_ERROR);
			}
			addTupleToMap(new Tuple(bytes, getKey().length));
		}
	}

	/**
	 * Method attempts to guess the key. Is simply a driver method and will
	 * call a recursive method guessKey(int index) to start guessing key from
	 * the key at byte index.
	 * 
	 * @return true if key is found with accuracy above THRESHOLD
	 *         false if key with accuracy above THRESHOLD cannot be found
	 */
	private boolean guessKey() {
		// Since we know IV size is C, we guess for K[C] first
		return guessKey(IV_SIZE);
	}

	/**
	 * Method attempts to recursively guess key at byte index.
	 * Method will attempt to guess each key byte by attacking the weak keys and
	 * using statistical analysis.
	 * 
	 * @param index
	 *            the byte of key to guess
	 * @return true if key can be found, false otherwise. Validation of key is
	 *         as specified in the method validateKey()
	 */
	private boolean guessKey(int index) {
		// Base case:
		// Finished guessing numToGuess bytes of key; proceed with brute force
		int numToGuess = getKey().length + IV_SIZE - NUM_TO_BF;
		if (index == numToGuess) {
			for (int i = 0; i < MAX_KEY_VAL; i++) {
				_key[numToGuess - IV_SIZE] = i;
				for (int j = 0; j < MAX_KEY_VAL; j++) {
					_key[numToGuess + 1 - IV_SIZE] = j;
					for (int k = 0; k < MAX_KEY_VAL; k++) {
						_key[numToGuess + 2 - IV_SIZE] = k;
						if (validateKey()) {
							return true;
						}
					}
				}
			}
			return false;
		}
		// Recursive case:
		// Initialize candidate and frequency
		int candidate = 0;
		indexFreqPair[] frequency = new indexFreqPair[KEY_SPACE];
		for (int i = 0; i < KEY_SPACE; i++) {
			frequency[i] = new indexFreqPair(i);
		}
		// Loop through all tuples and collate all possible key candidates
		for (Tuple tuple : getTuples().values()) {

			// FMS
			candidate = RC4Modified.KSA(tuple, getKey(), index);
			if (isValidCandidate(candidate)) {
				frequency[candidate].incFreq();
			}
			// Korek1
			candidate = RC4Modified.korek1(tuple, index);
			if (isValidCandidate(candidate)) {
				frequency[candidate].incFreq();
			}
			// Korek2
			candidate = RC4Modified.korek2(tuple, index);
			if (isValidCandidate(candidate)) {
				frequency[candidate].incFreq();
			}
			// Korek3
			candidate = RC4Modified.korek3(tuple, index);
			if (isValidCandidate(candidate)) {
				frequency[candidate].incFreq();
			}
			// Korek4
			candidate = RC4Modified.korek4(tuple, index);
			if (isValidCandidate(candidate)) {
				frequency[candidate].incFreq();
			}
			// Korek5
			candidate = RC4Modified.korek5(tuple, index);
			if (isValidCandidate(candidate)) {
				frequency[candidate].incFreq();
			}
			// Korek6
			candidate = RC4Modified.korek6(tuple, index);
			if (isValidCandidate(candidate)) {
				frequency[candidate].incFreq();
			}
			// Korek7
			candidate = RC4Modified.korek7(tuple, index);
			if (isValidCandidate(candidate)) {
				frequency[candidate].incFreq();
			}
			// Korek8
			candidate = RC4Modified.korek8(tuple, index);
			if (isValidCandidate(candidate)) {
				frequency[candidate].incFreq();
			}

		}
		// Sort the frequency in ascending order
		Arrays.sort(frequency);

		// Try amongst all top <KEY_BOUND> amount of keys for one key that is
		// valid. If no such key is found, return false.
		for (int i = 1; i <= KEY_BOUND; i++) {
			setKeyAt(index - IV_SIZE, frequency[KEY_SPACE - i].getIndex());
			if (guessKey(index + 1)) {
				return true;
			}
		}
		setKeyAt(index - IV_SIZE, KEY_INIT);
		return false;
	}

	/**
	 * Method to validate if key is correct.
	 * Method will take in tuples from the map and evaluate the first RSA output
	 * byte.
	 * Method will then compare the first byte and the first byte indicated in
	 * the tuple.
	 * If they're the same, it will count as 1 correct tuple.
	 * 
	 * @return true if there are at least 20 consecutive correct tuples. False
	 *         otherwise.
	 */
	private boolean validateKey() {
		// Counters for number of tuples correctly coded with the key
		int correct = 0;

		// For each tuple,
		for (Tuple tuple : getTuples().values()) {
			// Calculate the first byte of RC4 output
			int temp = RC4Modified.RC41Byte(tuple, getKey());

			// Check if that output is same as the one expected
			if (tuple.getOutput() == temp) {
				// increment number of correct tuple
				correct++;
				if (correct > THRESHOLD) {
					if (DEBUG_MODE) {
						showToUser("Keys: " + Arrays.toString(getKey()) + "\n");
						showToUser("Correct: " + correct + "\n");
					}
					return true;
				}
			} else {
				if (DEBUG_MODE) {
					showToUser("Keys: " + Arrays.toString(getKey()) + "\n");
					showToUser("Correct: " + correct + "\n");
				}
				// We're trying to achieve THRESHOLD continuous correct
				// Hence once we have 1 wrong, we will break out of checking and
				// return a false to reject this key
				break;
			}
		}
		return false;
	}

	/**
	 * Checks if candidate is a valid key. Key has acceptable range of
	 * [0,MAX_KEY_VAL) for each byte
	 * 
	 * @param candidate
	 *            to test
	 * @return true if candidate falls within acceptable range. false otherwise
	 */
	private boolean isValidCandidate(int candidate) {
		return candidate < MAX_KEY_VAL && candidate >= 0;
	}

	private void cleanup() {
		try {
			_fileReader.close();
		} catch (IOException e) {
			if (DEBUG_MODE) {
				e.printStackTrace();
				this.toString();
				showToUser(FAIL_CLOSE_READER);
			}
		}
	}

	/**
	 * Driver method for the WEP Cracker program.
	 * Program will eventually display the keys for each file cracked, or a
	 * message to show user that the file could not be cracked.
	 * 
	 * @param args
	 *            contains the array of file names to crack
	 */
	public static void main(String[] args) {
		// Checks if user invoked program with correct params
		if (args.length <= 0) {
			showToUser(INVALID_INVOCATION);
			System.exit(EXIT_WITH_ERROR);
		}

		// Create instance of cracker
		WEPCracker cracker = new WEPCracker();
		// For all filed specified by user
		for (int i = 0; i < args.length; i++) {
			cracker.crack(args[i]);
		}
		cracker.cleanup();
	}

	/* Getters and Setters */
	public String getFileName() {
		return _fileName;
	}

	public void setFileName(String fileName) {
		_fileName = fileName;
	}

	public void read(byte[] bytes) throws IOException {
		_fileReader.read(bytes);
	}

	public int[] getKey() {
		return _key;
	}

	public int getKeyAt(int index) {
		return _key[index];
	}

	public void setKey(int[] _key) {
		this._key = _key;
	}

	public void setKeyAt(int index, int value) {
		_key[index] = value;
	}

	public int getNumOfTuples() {
		return _numOfTuples;
	}

	public void setNumOfTuples(int _numOfTuples) {
		this._numOfTuples = _numOfTuples;
	}

	public Map<String, Tuple> getTuples() {
		return _tuples;
	}

	public Tuple getTuple(String identifier) {
		return _tuples.get(identifier);
	}

	public void setTuples(Map<String, Tuple> _tuples) {
		this._tuples = _tuples;
	}

	public void addTupleToMap(Tuple tuple) {
		_tuples.put(tuple.getIdentifier(), tuple);
	}

	/* helper methods */
	/**
	 * Method will show a message to user.
	 * This method does no additional formatting.
	 * 
	 * @param message
	 *            formatted message to be shown to user
	 */
	public static void showToUser(String message) {
		System.out.print(message);
	}

	/**
	 * Returns a string representation of this class in the format:
	 * 
	 * <pre>
	 * Filename		: _filename
	 * Key Length	: _key's length
	 * Key			: _Key
	 * No. of tuples: _numOfTuples
	 * Map size		: number of unique tuples
	 * </pre>
	 * 
	 * @return a String representation of this object
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Filename\t: " + getFileName() + "\n");
		sb.append("Key Length\t: " + getKey().length + "\n");
		sb.append("Key\t\t: ");
		for (int i = 0; i < getKey().length; i++) {
			sb.append(getKeyAt(i) + " ");
		}
		sb.append("\nNo of tuples\t: " + getNumOfTuples() + "\n");
		sb.append("MapSize\t\t: " + getTuples().size() + "\n");
		return sb.toString();
	}

}
