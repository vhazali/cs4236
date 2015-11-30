/**
 * Class that specifies the Index Frequency pair.
 * This pair consists of an index, as well as its frequency.
 * It will be used to perform Statistical analysis for the WEP Cracker.
 * 
 * @author Victor Hazali
 */
public class indexFreqPair implements Comparable<indexFreqPair> {
	private int	_index;
	private int	_freq;

	public indexFreqPair() {
		_index = 0;
		_freq = 0;
	}

	public indexFreqPair(int index) {
		_index = index;
		_freq = 0;
	}

	public void setIndex(int index) {
		_index = index;
	}

	public int getIndex() {
		return _index;
	}

	public void setFreq(int freq) {
		_freq = freq;
	}

	public void incFreq() {
		_freq++;
	}

	public int getFreq() {
		return _freq;
	}

	/**
	 * Two pairs are equal if and only if their index is the same.
	 * 
	 * @param o
	 *            object to compare with
	 * @return true if o is another Index Frequency Pair with the same index
	 */
	@Override
	public boolean equals(Object o) {
		if (o == null) {
			return false;
		}
		if (o == this) {
			return true;
		}
		if (!(o instanceof indexFreqPair)) {
			return false;
		}

		indexFreqPair other = (indexFreqPair) o;
		if (_index == other.getIndex()) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Returns a negative integer, zero, or a positive integer as this object is
	 * less than, equal to, or greater than the specified object.
	 * The comparison is based on the natural ordering of the frequency of the
	 * pairs.
	 * 
	 * @param o
	 *            object to compare with
	 * @return -1 if this is smaller than o, 0 if this is equals to o, 1 if this
	 *         is larger than o
	 */
	@Override
	public int compareTo(indexFreqPair o) {
		if (_freq < o.getFreq()) {
			return -1;
		}
		else if (_freq == o.getFreq()) {
			return 0;
		}
		else {
			return 1;
		}
	}

	/**
	 * Returns a string representation of this class in the format:
	 * 
	 * <pre>
	 * Index: _index 
	 * Freq: _freq
	 * </pre>
	 * 
	 * @return a string representation of this object.
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Index: " + getIndex() + "\n");
		sb.append("Freq : " + getFreq() + "\n");
		return sb.toString();
	}

}
