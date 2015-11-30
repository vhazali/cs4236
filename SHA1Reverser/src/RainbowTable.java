import java.io.BufferedWriter;
import java.io.FileWriter;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.util.Set;

/**
 * Class to build a rainbow table
 * 
 * @author Victor Hazali
 */
public class RainbowTable {

	// Change this for the length of word to get from the reversing
	private static final int	WORD_BITS			= 24;
	public static final int		WORD_LENGTH			= WORD_BITS / 8;
	// Change this for the length of digest in bits
	private static final int	DIGEST_BITS			= 160;
	public static final int		DIGEST_LENGTH		= DIGEST_BITS / 8;
	// Change this to alter the chain length. Longer chain length => smaller
	// rainbow table, but longer computation time when cracking
	private static final double	CHAIN_LENGTH_BITS	= 7.1;
	public static final int		CHAIN_LENGTH		= (int) Math
															.pow(2,
																	CHAIN_LENGTH_BITS);
	public static final int		CHAIN_COUNT			= (int) Math
															.pow(2,
																	WORD_BITS
																			- CHAIN_LENGTH_BITS
																			- 1);
	public static final int		TABLE_SIZE			= (int) Math.pow(2,
															WORD_BITS - 3);
	// Change this for the name of file containing the rainbow table
	public static final String	TABLE_FILENAME		= "Rainbow Table";
	// Change this for the amount of bytes of digest to write to table. Do not
	// change the +1. The longer number of bytes should make it more accurate.
	// Minimally should be 5, due to reduction function. Max is 20.
	public static final int		DIGEST_WRITE_LENGTH	= 3;

	// Member variables
	private Map<String, String>	_rainbowTable;
	private Set<String>			_processedMessages;

	public RainbowTable() {
		initialise();
	}

	private void initialise() {
		_rainbowTable = new HashMap<String, String>();
		_processedMessages = new HashSet<String>();
	}

	/**
	 * Builds the rainbow table and writes it to a file, where the filename is
	 * specified in TABLE_FILENAME
	 * 
	 * @return true if successfully built. False otherwise
	 */
	public boolean buildTable() {
		try {
			StopWatch timer = new StopWatch();
			timer.start();
			byte[] newMessage = new byte[WORD_LENGTH];
			byte[] newDigest = new byte[DIGEST_LENGTH];
			while (_rainbowTable.size() < CHAIN_COUNT) {
				newMessage = getRandomMessage();
				if (newMessage != null) {
					newDigest = buildChain(newMessage);
					if (newDigest != null) {
						if (!_rainbowTable.containsKey(newDigest)) {
							_rainbowTable.put(toHexString(newDigest),
									toHexString(newMessage));
						}
					}
				}
			}
			timer.stop();
			if (Inverter.DEBUG_MODE) {
				System.out.println("Finished building chains in "
						+ timer.getTime() + " seconds.");
			}

			timer.start();
			writeToFile();
			timer.stop();
			if (Inverter.DEBUG_MODE) {
				System.out.println("Finished writing to file in "
						+ timer.getTime() + " seconds.");
				System.out.println("Number of entries in file: "
						+ _rainbowTable.size());
			}
			return true;
		} catch (Exception e) {
			if (Inverter.DEBUG_MODE) {
				System.out.println("Failed to build table");
				e.printStackTrace();
				System.exit(1);
			}
		}
		return false;
	}

	/**
	 * Method builds the chain based on the head message supplied to the method.
	 * It will build a chain of length specified in CHAIN_LENGTH and then return
	 * the tail digest if chain was built successfully. Otherwise, a null object
	 * is returned instead.
	 * 
	 * @param message
	 *            the head message for the chain
	 * @return A byte array containing the tail digest if chain was built
	 *         successfully. Otherwise, a null object.
	 */
	private byte[] buildChain(byte[] message) {
		try {
			byte[] currDigest = new byte[DIGEST_LENGTH];
			byte[] currMessage = Arrays.copyOf(message, message.length);
			for (int i = 0; i < CHAIN_LENGTH; i++) {
				currDigest = hash(currMessage);
				currMessage = reduce(currDigest, i);
				_processedMessages.add(toHexString(currMessage));
			}
			currDigest = hash(currMessage);
			return currDigest;
		} catch (Exception e) {
			if (Inverter.DEBUG_MODE) {
				System.out.println("Failed to build chain");
				e.printStackTrace();
			}
			return null;
		}
	}

	/**
	 * Returns a random message that has yet to be processed.
	 * Message conforms to the length that is specified by WORD_LENGTH
	 * 
	 * @return A byte array containing the randomly generated message. If any
	 *         exception is caught, then returns null.
	 */
	private byte[] getRandomMessage() {
		try {
			byte[] message = new byte[WORD_LENGTH];
			Random msgGenerator = new Random();
			do {
				msgGenerator.nextBytes(message);
			} while (isProcessed(message));
			_processedMessages.add(toHexString(message));
			return message;
		} catch (Exception e) {
			if (Inverter.DEBUG_MODE) {
				System.out.println("Failed to get random message");
				e.printStackTrace();
			}
			return null;
		}
	}

	/**
	 * Checks whether the message has been processed before.
	 * A message is only set as processed when it was used as a starting message
	 * and when it is an intermediate message in a chain.
	 * Method relies on an underlying Set data structure, and uses its
	 * contains() function.
	 * 
	 * @param message
	 *            the message to test
	 * @return true if it is already processed, false otherwise.
	 */
	private boolean isProcessed(byte[] message) {
		return _processedMessages.contains(toHexString(message));
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
			MessageDigest encoder = MessageDigest
					.getInstance(Inverter.HASH_ALGO);
			encoder.reset();
			byte[] result = encoder.digest(message);
			return result;
		} catch (Exception e) {
			if (Inverter.DEBUG_MODE) {
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
			if (Inverter.DEBUG_MODE) {
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

	private void writeToFile() throws Exception {
		BufferedWriter bw = new BufferedWriter(new FileWriter(TABLE_FILENAME));
		for (Map.Entry<String, String> entry : _rainbowTable.entrySet()) {
			// Write head message
			bw.write(entry.getValue());
			bw.write(" ");
			// write tail
			bw.write(entry.getKey().substring(0, DIGEST_WRITE_LENGTH * 2));
			bw.write("\n");
		}
		bw.flush();
		bw.close();
	}

	public void test() {
		testHash();

		testBuildChain();
	}

	private void testBuildChain() {
		String sample = "abcdef";
		byte[] message = messageToByteArray(sample);
		byte[] currDigest = new byte[DIGEST_LENGTH];
		byte[] currMessage = Arrays.copyOf(message, message.length);
		for (int i = 0; i < CHAIN_LENGTH; i++) {
			currDigest = hash(currMessage);
			System.out.println("Digest " + i + " : " + toHexString(currDigest));
			currMessage = reduce(currDigest, i);
			System.out.println("Message " + (i + 1) + " : "
					+ toHexString(currMessage));
			_processedMessages.add(toHexString(currMessage));
		}
		currDigest = hash(currMessage);
		System.out.println("Digest " + CHAIN_LENGTH + " : "
				+ toHexString(currDigest));
	}

	private void testHash() {
		String sample = "abcdef";
		System.out.println("Sample string:" + sample);
		System.out.println("Hashed sample: "
				+ toHexString(hash(messageToByteArray(sample))));
	}

	public static void main(String[] args) {
		RainbowTable rt = new RainbowTable();
		StopWatch timer = new StopWatch();

		if (Inverter.DEBUG_MODE) {
			rt.test();
		}

		timer.start();
		if (rt.buildTable()) {
			timer.stop();
			System.out.println("Succeed in building Rainbow Table in "
					+ timer.getTime() + " seconds.\n");
		} else {
			timer.stop();
			System.out.println("Failed in building Rainbow Table in "
					+ timer.getTime() + " seconds.\n");
			;
		}
	}
}