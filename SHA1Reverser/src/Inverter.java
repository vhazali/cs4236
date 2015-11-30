import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 * Class to perform a hash inversion using a rainbow table.
 * Class is dependent on RainbowTable.java
 * Ensure that RainbowTable.java is executed before this, otherwise class will
 * fail to find any message.
 * 
 * @author Victor Hazali
 */
public class Inverter {

	// Change this to change the hashing algorithm used by the rainbow table
	public static final String	HASH_ALGO			= "SHA-1";
	public static final boolean	DEBUG_MODE			= false;
	// Change this to change where to read the digest from
	private static final String	INPUT_FILENAME		= "Sample Input";
	// Change this to define how many digests there will be in the input file
	private static final int	INPUT_DIGEST_COUNT	= 1000;
	// Change this to specify where to write the result to
	private static final String	RESULT_FILENAME		= "result.txt";

	// member variables
	private Map<String, String>	_rainbowTable;
	Scanner						_digestScanner;
	private Writer				_resultWriter;

	public Inverter() {
		initialise();
	}

	private void initialise() {
		_rainbowTable = new HashMap<String, String>();
		try {
			_digestScanner = new Scanner(new BufferedInputStream(
					new FileInputStream(INPUT_FILENAME)));
			_resultWriter = new BufferedWriter(new FileWriter(RESULT_FILENAME));
			writeResult("START");
		} catch (FileNotFoundException e) {
			if (DEBUG_MODE) {
				System.out.println("Failed to open digest input file");
				e.printStackTrace();
			}
			System.exit(1);
		} catch (IOException e) {
			if (DEBUG_MODE) {
				System.out.println("Failed to write to result file");
				e.printStackTrace();
			}
			System.exit(1);
		}
		populateTable();
	}

	/**
	 * Method reads the rainbow table from the file and populate the table into
	 * the map
	 */
	private void populateTable() {
		try {
			Scanner sc = new Scanner(new BufferedInputStream(
					new FileInputStream(RainbowTable.TABLE_FILENAME)));
			while (sc.hasNext()) {
				String message = sc.next();
				String digest = sc.next();
				digest = digest.concat("0000000000000000000000000000000000");
				_rainbowTable.put(digest, message);
			}
			System.out.println("Rainbow Table read from file. Size of table: "
					+ _rainbowTable.size());
			sc.close();
			writeResult("TOTAL" + _rainbowTable.size());
			writeResult("READ DONE");
		} catch (FileNotFoundException e) {
			if (DEBUG_MODE) {
				e.printStackTrace();
				System.out.println("Failed to read table");
			}
			System.exit(1);
		}
	}

	/**
	 * Method takes in a target digest, and searches for the corresponding
	 * message that leads to this digest.
	 * 
	 * @param digest
	 *            byte array containing the target digest
	 * @return a byte array containing the target message if it can be found. If
	 *         it cannot be found, a null is returned.
	 */
	private byte[] search(byte[] digest) {
		assert (digest.length == RainbowTable.DIGEST_LENGTH);

		/* find for digest in table */
		// Loop from the back, to do less reduction
		for (int i = RainbowTable.CHAIN_LENGTH; i >= 0; i--) {
			// Index i indicates the guess of which index the digest is in our
			// table
			byte[] currMessage = new byte[RainbowTable.WORD_LENGTH];
			// byte[] currDigest = Arrays.copyOf(digest, digest.length);
			byte[] currDigest = Arrays.copyOf(digest, digest.length);
			byte[] targetMessage = null;

			// Loop to decide how many reduction to do
			for (int j = i; j < RainbowTable.CHAIN_LENGTH; j++) {
				currMessage = reduce(currDigest, j);
				currDigest = hash(currMessage);
			}

			// If the digest can be found in the table
			if (_rainbowTable.containsKey(toHexString(currDigest))) {

				// Rebuild the chain for this digest
				targetMessage = rebuildChain(
						_rainbowTable.get(toHexString(currDigest)),
						toHexString(digest));

				// If the chain was rebuilt successfully
				if (targetMessage != null) {
					return targetMessage;
				}
			}
		}
		return null;
	}

	/**
	 * Method takes in a String containing one of the starting point of the
	 * chains. Method then rebuilds the chain until it gets the target digest.
	 * Method will then return a byte array containing the message that hashes
	 * to the target digest.
	 * 
	 * @param headMessage
	 *            String variable containing the start of a chain
	 * @param targetDigest
	 *            String variable containing the target digest
	 * @return a byte array containing the target message if it can be found. If
	 *         it cannot be found, a null is returned.
	 */
	private byte[] rebuildChain(String headMessage, String targetDigest) {
		byte[] currMessage = messageToByteArray(headMessage);
		byte[] targDigest = digestToByteArray(targetDigest);
		byte[] currDigest = hash(currMessage);
		for (int i = 0; i <= RainbowTable.CHAIN_LENGTH; i++) {
			// if (toHexString(currDigest).equals(targetDigest)) {
			// return currMessage;
			// }
			if (isEquivalentDigest(targDigest, currDigest)) {
				return currMessage;
			}
			currMessage = reduce(currDigest, i);
			currDigest = hash(currMessage);
		}
		return null;
	}

	/**
	 * Method to read the next digest from the file specified by INPUT_FILENAME.
	 * Method will "mask" the bytes after RainbowTable.DIGEST_WRITE_LENGTH with
	 * byte 0
	 * 
	 * @return a byte array containing the digest read.
	 */
	private byte[] readNextDigest() {
		ByteBuffer bf = ByteBuffer.allocate(20);
		for (int j = 0; j < 5; j++) {
			bf.putInt((int) _digestScanner.nextLong(16));
		}
		byte[] result = bf.array();
		Arrays.fill(result, RainbowTable.DIGEST_WRITE_LENGTH,
				RainbowTable.DIGEST_LENGTH, (byte) 0);
		return result;
	}

	/**
	 * Method takes a byte array and performs hashing on the array.
	 * Hashing algorithm is specified by HASH_ALGO.
	 * If hashing were to fail, returns a null instead.
	 * 
	 * @param message
	 *            byte array containing message to be hashed
	 * @return a byte array containing the digest
	 */
	private byte[] hash(byte[] message) {
		try {
			MessageDigest encoder = MessageDigest.getInstance(HASH_ALGO);
			encoder.reset();
			byte[] result = encoder.digest(message);
			Arrays.fill(result, RainbowTable.DIGEST_WRITE_LENGTH,
					RainbowTable.DIGEST_LENGTH, (byte) 0);
			return result;
		} catch (Exception e) {
			if (DEBUG_MODE) {
				System.out.println("Failed to perform hashing");
				e.printStackTrace();
			}
			System.exit(1);
		}
		return null;
	}

	/**
	 * Method takes a byte array and performs reduction on the array.
	 * Reduction algorithm ensures that the result is within the set of possible
	 * messages.
	 * If reduction were to fail, returns a null instead.
	 * 
	 * @param digest
	 *            byte array containing digest to be reduced
	 * @param index
	 *            the reduction index, to choose which reduction function to
	 *            perform
	 * @return a byte array containing the message obtained from reduction
	 */
	private byte[] reduce(byte[] digest, int index) {
		try {
			byte[] message = new byte[RainbowTable.WORD_LENGTH];
			message[0] = (byte) (digest[0] + index);
			message[1] = (byte) (digest[1] + index);
			message[2] = (byte) (digest[2] + index);
			return message;
		} catch (Exception e) {
			if (DEBUG_MODE) {
				System.out.println("Failed to perform reduction");
				e.printStackTrace();
			}
			System.exit(1);
		}
		return null;
	}

	/**
	 * Method takes an array of bytes and converts it into a string of
	 * hexadecimal representation
	 * 
	 * @param byteArr
	 *            the byteArray to convert
	 * @return A String that is the hexadecimal representation of the byteArr
	 */
	private String toHexString(byte[] byteArr) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < byteArr.length; i++) {
			sb.append(Integer.toString((byteArr[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return sb.toString();
	}

	/**
	 * Method takes a string of hexadecimal representation and converts it into
	 * a byte array
	 * 
	 * @param hexString
	 *            A string containing hexadecimal representation
	 * @return a byte array representation of the string
	 */
	private byte[] messageToByteArray(String hexString) {
		ByteBuffer bf = ByteBuffer.allocate(4);
		Scanner sc = new Scanner(hexString);
		bf.putInt(sc.nextInt(16));
		sc.close();
		return Arrays.copyOfRange(bf.array(), 1, 4);
	}

	/**
	 * Method takes a string of hexadecimal representation and converts it into
	 * a byte array
	 * 
	 * @param hexString
	 *            A string containing hexadecimal representation
	 * @return a byte array representation of the string
	 */
	private byte[] digestToByteArray(String hexString) {
		try {
			int len = hexString.length();
			byte[] data = new byte[RainbowTable.DIGEST_LENGTH];
			for (int i = 0; i < len; i += 2) {
				data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
						+ Character.digit(hexString.charAt(i + 1), 16));
			}
			return data;
		} catch (Exception e) {
			System.out.println("Failed to process string: " + hexString);
			e.printStackTrace();
			System.exit(1);
		}
		return null;
	}

	/**
	 * Method to write the result into the file. Is followed by a newline.
	 * Method does no additional formatting except for appending a newline
	 * character after the message.
	 * 
	 * @param message
	 *            the target message that is guessed.
	 */
	private void writeResult(String message) {
		try {
			_resultWriter.write(message + "\n");
		} catch (IOException e) {
			if (DEBUG_MODE) {
				System.out.println("Failed to write message to file");
				e.printStackTrace();
			}
			System.exit(1);
		}
	}

	/**
	 * Checks if two digests are equal. This method performs a check only until
	 * the index specified by DIGEST_WRITE_LENGTH
	 * 
	 * @param targetDigest
	 * @param calculatedDigest
	 * @return true if all the elements in both arrays are equal. False
	 *         otherwise
	 */
	private boolean isEquivalentDigest(byte[] targetDigest,
			byte[] calculatedDigest) {

		for (int i = 0; i < RainbowTable.DIGEST_WRITE_LENGTH; i++) {
			if (calculatedDigest[i] != targetDigest[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Method performs all the tests required
	 */
	public void test() {
		testByteStringConversion();
		testHash();
		testRebuildChain();
		testSearch();
		int count = 0, totalFound = 0, totalNotFound = 0;
		for (Map.Entry<String, String> entry : _rainbowTable.entrySet()) {
			if (count >= 100) {
				break;
			}
			byte[] digest = hash(messageToByteArray(entry.getValue()));
			byte[] message = search(digest);
			if (message != null
					&& Arrays.equals(messageToByteArray(entry.getValue()),
							message)) {
				totalFound++;
			}
			else {
				totalNotFound++;
			}
			count++;
		}
		System.out.println("Total found: " + totalFound);
		System.out.println("Total not found: " + totalNotFound);
	}

	/**
	 * Method will test to ensure that the conversion from a hex string, to a
	 * byte array and back is correct. It is correct if and only if the result
	 * is the same as the initial string.
	 */
	private void testByteStringConversion() {
		String sample = "a80b450000000000000000000000000000000000";
		byte[] digest = digestToByteArray(sample);
		System.out.println("Converted to array: " + Arrays.toString(digest));
		if (toHexString(digest).equals(sample)) {
			System.out.println("Byte String conversion success");
		} else {
			System.out.println("Byte String conversion failed");
		}
	}

	/**
	 * Tests the hashing method by giving it a sample string.
	 * The result is not being compared, but rather displayed to the user.
	 */
	private void testHash() {
		String sample = "abcdef";
		System.out.println("Sample string:" + sample);
		byte[] hashed = hash(messageToByteArray(sample));
		System.out.println("Hashed sample: " + Arrays.toString(hashed));
	}

	/**
	 * Tests the rebuildChain method. Method will pass in a sample string as the
	 * head and display all the intermediate digests and messages until the
	 * whole chain is built.
	 */
	private void testRebuildChain() {
		String sample = "abcdef";
		byte[] currMessage = messageToByteArray(sample);
		byte[] currDigest = hash(currMessage);
		System.out.println("Digest 0 : " + toHexString(currDigest));
		for (int i = 0; i < RainbowTable.CHAIN_LENGTH; i++) {
			// if (toHexString(currDigest).equals(targetDigest)) {
			// return currMessage;
			// }
			currMessage = reduce(currDigest, i);
			System.out.println("Message " + (i + 1) + " : "
					+ toHexString(currMessage));
			currDigest = hash(currMessage);
			System.out.println("Digest " + (i + 1) + " : "
					+ toHexString(currDigest));
		}
	}

	/**
	 * Method will test the search method. It will pass in sample digests to
	 * search for and tests if the result is correct.
	 * The test cases are to be changed when: there is a change in the
	 * reduction/hashing function, there is a change in
	 * RainbowTable.DIGEST_WRITTEN_LENGTH.
	 * In order to change the values, look at the output from the
	 * testRebuildChain() method.
	 */
	private void testSearch() {
		_rainbowTable.put("c28b690000000000000000000000000000000000",
				"abcdef");
		String sample;
		byte[] message;
		// Digest 128 for head "abcdef"
		sample = "c28b690000000000000000000000000000000000";
		message = search(digestToByteArray(sample));
		if (message == null) {
			System.out.println("Failed to find message for digest 128");
		}
		else if (toHexString(message).equals("565043")) {
			System.out.println("Found message for digest 128");
		} else {
			System.out.println("Failed to find message for digest 128");
		}

		// Digest 127 for head "abcdef"
		sample = "d7d1c40000000000000000000000000000000000";
		message = search(digestToByteArray(sample));
		if (message == null) {
			System.out.println("Failed to find message for digest 127");
		}
		else if (toHexString(message).equals("588aa5")) {
			System.out.println("Found message for digest 127");
		} else {
			System.out.println("Failed to find message for digest 127");
		}

		// Digest 126 for head "abcdef"
		sample = "da0c270000000000000000000000000000000000";
		message = search(digestToByteArray(sample));
		if (message == null) {
			System.out.println("Failed to find message for digest 126");
		}
		else if (toHexString(message).equals("66230a")) {
			System.out.println("Found message for digest 126");
		} else {
			System.out.println("Failed to find message for digest 126");
		}

		// Digest 64 for head "abcdef"
		sample = "779c6d0000000000000000000000000000000000";
		message = search(digestToByteArray(sample));
		if (message == null) {
			System.out.println("Failed to find message for digest 64");
		}
		else if (toHexString(message).equals("98a0f7")) {
			System.out.println("Found message for digest 64");
		} else {
			System.out.println("Failed to find message for digest 64");
		}

		// Digest 2 for head "abcdef"
		sample = "60123c0000000000000000000000000000000000";
		message = search(digestToByteArray(sample));
		if (message == null) {
			System.out.println("Failed to find message for digest 2");
		}
		else if (toHexString(message).equals("388da1")) {
			System.out.println("Found message for digest 2");
		} else {
			System.out.println("Failed to find message for digest 2");
		}

		// Digest 1 for head "abcdef"
		sample = "378ca00000000000000000000000000000000000";
		message = search(digestToByteArray(sample));
		if (message == null) {
			System.out.println("Failed to find message for digest 1");
		}
		else if (toHexString(message).equals("3cd5ee")) {
			System.out.println("Found message for digest 1");
		} else {
			System.out.println("Failed to find message for digest 1");
		}

		// Digest 0 for head "abcdef"
		sample = "3cd5ee0000000000000000000000000000000000";
		message = search(digestToByteArray(sample));
		if (message == null) {
			System.out.println("Failed to find message for digest 0");
		}
		else if (toHexString(message).equals("abcdef")) {
			System.out.println("Found message for digest 0");
		} else {
			System.out.println("Failed to find message for digest 0");
		}

		_rainbowTable.remove("c28b690000000000000000000000000000000");
	}

	/**
	 * Method to close all resources used
	 */
	private void cleanup() {
		try {
			_resultWriter.flush();
			_resultWriter.close();
			_digestScanner.close();
		} catch (IOException e) {
			if (DEBUG_MODE) {
				System.out.println("Failed to close file writer");
				e.printStackTrace();
			}
		}
	}

	/**
	 * Driving method to perform the cracking of the digests
	 * Method will read target digest, attempt to crack the digest. The result
	 * will then be stored in a file specified by RESULT_FILENAME.
	 * If the message is not cracked from the rainbow table, it will write a 0.
	 * If the digest could not be read for any reasons, it will write a 00.
	 * Otherwise, it will write the message found as specified by writeResult.
	 */
	public void run() {
		int totalNotFound = 0, totalFound = 0;

		for (int i = 0; i < INPUT_DIGEST_COUNT; i++) {
			byte[] targetDigest = new byte[RainbowTable.DIGEST_LENGTH];
			byte[] targetMessage = new byte[RainbowTable.WORD_LENGTH];
			targetDigest = readNextDigest();
			if (targetDigest == null) {
				// Failed to read this digest, ignore and move on to the next
				// digest
				totalNotFound++;
				writeResult("    00");
				continue;
			}
			targetMessage = search(targetDigest);
			if (targetMessage == null) {
				// Failed to find message for this digest
				totalNotFound++;
				writeResult("     0");
				continue;
			}
			else {
				totalFound++;
				writeResult(toHexString(targetMessage));
			}
		}
		System.out.println("Total number of words found is: " + totalFound);
		writeResult("The total number of words found is: " + totalFound);
		System.out.println("C = " + (float) totalFound / INPUT_DIGEST_COUNT
				* 100
				+ "%");
		if (DEBUG_MODE) {
			System.out.println("Total not found: " + totalNotFound);
		}
		cleanup();
	}

	public static void main(String[] args) {
		StopWatch timer = new StopWatch();
		float T = timeTest();
		float t;
		// Perform reading of rainbow table
		timer.start();
		Inverter inv = new Inverter();
		timer.stop();
		System.out.println("Read table in " + timer.getTime() + " seconds");
		// Perform tests
		if (DEBUG_MODE) {
			timer.start();
			inv.test();
			timer.stop();
			System.out.println("Test completed in " + timer.getTime()
					+ " seconds");
		}
		// Perform the actual cracking
		timer.start();
		inv.run();
		timer.stop();
		t = timer.getTime();
		System.out.println("Completed in " + t + " seconds");
		float F = 1000 * T / t;
		System.out.println("Speedup factor: " + F);
	}

	/**
	 * Method does a time test on how long it takes to perform 2^23 hashes.
	 * Hashing algorithm used will be specified by HASH_ALGO
	 * 
	 * @return a float variable containing the time taken in seconds
	 */
	private static float timeTest() {
		StopWatch timer = new StopWatch();
		float T = 0;
		timer.start();
		MessageDigest encoder;
		try {
			encoder = MessageDigest.getInstance(HASH_ALGO);
			byte[] input = new byte[3];
			for (int i = 0; i < (1 << 23); i++) {
				encoder.digest(input);
			}
			timer.stop();
			T = timer.getTime();
			System.out.println("T: " + T + " seconds");
			return T;
		} catch (NoSuchAlgorithmException e) {
			if (DEBUG_MODE) {
				System.out.println("Failed to perform timetest");
				e.printStackTrace();
			}
		}
		return 0;
	}
}