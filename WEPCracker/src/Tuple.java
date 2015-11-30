import java.util.Arrays;

/**
 * Class that specifies the ADT Tuple.
 * Contains an array of IVs as well as one byte of output.
 * The class contains an identifier which is simply the IV values expressed in a
 * string using Arrays.toString().
 * 
 * @author Victor Hazali
 */
public class Tuple {

	private static final int	IV_OFFSET		= 0;
	private static final int	RESULT_OFFSET	= WEPCracker.IV_SIZE;
	public static final String	ARG_MISMATCH	= "Incorrect number of arguments for tuple!\n";

	private int[]				_IV;
	private int					_output;
	private String				_identifier;

	/* Constructors */
	public Tuple() {
		initialise();
	}

	public Tuple(byte[] tuple, int keyLength)
			throws IllegalArgumentException {
		// Checks for correct number of elements: IV_KNOWN_SIZE of IVs, and 1
		// more for the first byte of RC4 output
		if (tuple.length != WEPCracker.IV_SIZE + 1) {
			throw new IllegalArgumentException(ARG_MISMATCH);
		}

		initialise();
		// Copies values
		setIV(new int[WEPCracker.IV_SIZE]);
		// Binary addition of 0xFF is required to ensure that it's an unsigned
		// int
		for (int i = IV_OFFSET; i < WEPCracker.IV_SIZE; i++) {
			setIVIndex(i, tuple[i] & 0xFF);
		}
		setIdentifier(Arrays.toString(getIV()));
		setOutput(tuple[RESULT_OFFSET] & 0xFF);
	}

	/* Accessors and Modifiers */
	public int[] getIV() {
		return _IV;
	}

	public int getIVAt(int index) throws IndexOutOfBoundsException {
		if (index >= getIV().length) {
			throw new IndexOutOfBoundsException();
		}
		return _IV[index];
	}

	public void setIV(int[] IV) {
		_IV = IV;
	}

	public void setIVIndex(int index, int value)
			throws IndexOutOfBoundsException {
		if (index >= getIV().length) {
			throw new IndexOutOfBoundsException();
		}

		_IV[index] = value;
	}

	public int getOutput() {
		return _output;
	}

	public void setOutput(int output) {
		_output = output;
	}

	public String getIdentifier() {
		return _identifier;
	}

	public void setIdentifier(String id) {
		_identifier = id;
	}

	/* Private methods */

	/**
	 * Initializes the fields of the class
	 * Creates a new key array with size 0
	 * output = 0
	 * known key length = IV_KNOWN_SIZE
	 */
	private void initialise() {
		setIdentifier("");
		setIV(new int[0]);
		setOutput(0);
	}

	/* Public methods */

	/**
	 * Returns a string representation of this class in the format:
	 * 
	 * <pre>
	 * IV: all bytes of IV
	 * Output: output byte
	 * </pre>
	 * 
	 * @return a string representation of this object
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("IV: ");
		for (int i = 0; i < _IV.length; i++) {
			sb.append(_IV[i] + " ");
		}
		sb.append("\n" + "Output: " + _output + "\n");
		return sb.toString();
	}

	/**
	 * Two Tuples are equal if and only if they have the same identifier.
	 * In other words, they must have the same byts for IV.
	 */
	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (!(o instanceof Tuple))
			return false;
		Tuple other = (Tuple) o;
		return other.getIdentifier().equals(other.getIdentifier());
	}

	@Override
	public int hashCode() {
		return getIdentifier().hashCode();
	}
}
