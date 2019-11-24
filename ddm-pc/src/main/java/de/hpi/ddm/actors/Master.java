package de.hpi.ddm.actors;

import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;

import akka.actor.*;
import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Output;
import de.hpi.ddm.structures.HexStringParser;
import lombok.Data;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

import static java.nio.ByteBuffer.wrap;

public class Master extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "master";

	// Show information about how many hashes still need to be cracked.
	// TODO: Set to false
	private static final boolean LOG_PROGRESS = true;

	// ---- Assumptions on the limitations of large messages
	private static final boolean VALIDATE_MEMORY_ESTIMATIONS = false;
	// The master will use a large message channel for transmitting the hashes we are trying to solve.
	// This is by default limited to 2MiB. With huge input files, it might increase performance to increase this buffer.
	// https://doc.akka.io/docs/akka/current/general/configuration-reference.html
	private static final int MAXIMUM_MESSAGE_BYTES = 2 * 1024 * 1024;
	// 32kB were measured on a huge message (4 * 1024 * 1024 Hashes = 136MB of serialized data).
	// For smaller messages, it's usually less
	private static final int UNSOLVED_HASHES_MESSAGE_OVERHEAD = 32 * 1024;
	private static final int REQUIRED_SPACE_PER_STORED_HASH = 34; // Bytes, measured.
	private static final int HASHES_PER_UNSOLVED_HASHES_MESSAGE =
			(MAXIMUM_MESSAGE_BYTES - UNSOLVED_HASHES_MESSAGE_OVERHEAD) / REQUIRED_SPACE_PER_STORED_HASH;

	// Each hash has 32 byte of data -- associated ByteBuffer and array objects might add some overhead.
	private static final long ESTIMATED_MEMORY_USAGE_PER_HASH = 64;

	// How many hashes can the master and each worker hold in memory? This is kind of fuzzy as other resources grow
	// linearly with the hash count as well. For 4G RAM, if 2G are usable for the hashes, assuming each hash has 32 byte
	// of data and 32 byte overhead for ByteBuffer and array objects, we get
	// 2 * 1024 * 1024 * 1024 / ESTIMATED_MEMORY_USAGE_PER_HASH = 33554432
	// For the Odin / Thor cluster, assuming 30GB of RAM, we propose trying
	// 30 * 1024 * 1024 * 1024 / ESTIMATED_MEMORY_USAGE_PER_HASH = 503316480
	private static final long MAXIMUM_HASHES_TO_FIT_IN_MEMORY = 33554432;

	// It does not make sense to build a work packet that no mutable character left
	private static final long MINIMUM_PASSWORD_PACKET_LENGTH_LEFT = 1;
	// For hints, it does not make sense to build a work packet that has less than 5 chars left (5! = 720)
	private static final long MINIMUM_HINT_PACKET_LENGTH_LEFT = 5;
	// How many work packets do we want to build for hints and password (=> how many workers can we parallelize for?)
	// Set as low as possible. Each packet occupies heap space in the master until its solved.
	// 48 should be enough for all usual computer setup and the RasPi cluster. Increase to 240 for the Odin cluster.
	// The program will generate the next count of packets possible with our distribution scheme
	// Thus, the value you set here and the produced packet count this might differ significantly (factor alphabet size)
	private static final long TARGET_WORK_PACKET_COUNT = 48;

	// Should we try to find out if some passwords have a reduced alphabet that is a subset of other passwords?
	// This required O(n^2) with n = count of distinct password alphabets, so for 100 or 1000 lines this should be fine
	// For really huge files you can turn this off, it may happen that we do a lot of unnecessary hashing then, though.
	private static final boolean CHECK_PASSWORD_ALPHABETS_FOR_SUBSETS = true;

	public static Props props(final ActorRef reader, final ActorRef collector) {
		return Props.create(Master.class, () -> new Master(reader, collector));
	}

	private Master(final ActorRef reader, final ActorRef collector) {
		this.reader = reader;
		this.collector = collector;
		this.workers = new ArrayList<>();

		// Workers may ask us before we started reading -> would give null pointer exceptions
		this.actorsWaitingForUnsolvedReferenceMessages = new HashSet<>();
		this.actorsWaitingForUnsolvedMessages = new HashMap<>();
	}

	////////////////////
	// Actor Messages //
	////////////////////

	// MasterSystem to Master: Start reading the csv file.
	@Data
	public static class StartMessage implements Serializable {
		private static final long serialVersionUID = -50374816448627600L;
	}

	// Reader to master: List of lines read from the csv file.
	@Data @NoArgsConstructor @AllArgsConstructor
	static class BatchMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private List<String[]> lines;
	}

	// Worker to master: I was born.
	@Data
	static class RegistrationMessage implements Serializable {
		private static final long serialVersionUID = 3303081601659723997L;
	}

	// Master to self: I'm done reading the file. Create hint work packages.
	@Data
	private static class CreateHintWorkPacketsMessage implements Serializable {
		private static final long serialVersionUID = 4016375330343989553L;
	}

	// Master to Worker: I have a new set of hashes. Unset yours and query the new ones.
	@Data @NoArgsConstructor @AllArgsConstructor
	static class GetUnsolvedHashesMessage implements Serializable {
		private static final long serialVersionUID = 5208022574113756999L;
        // required so that if the worker gets the hashes from the local data provider, it's already the new ones.
		private long iterationId;
	}

	// Worker to Master: Send me the unsolved hashes of the current iteration, starting from chunkOffset.
	@Data @NoArgsConstructor @AllArgsConstructor
	static class SendUnsolvedHashesMessage implements Serializable {
		private static final long serialVersionUID = 8996201587099482364L;
		private int chunkOffset;
        private long iterationId;
	}

	// Worker to data providing Worker or Master: Send me the unsolved hashes, use a reference.
	@Data @NoArgsConstructor @AllArgsConstructor
	static class SendUnsolvedHashesReferenceMessage implements Serializable {
		private static final long serialVersionUID = 7887543928732622009L;
        private long iterationId;
	}

	// Master to self: Send out UnsolvedHashesMessages to everyone waiting for one.
	@Data
	static class DistributeUnsolvedHashesMessage implements Serializable {
		private static final long serialVersionUID = 5705955020161158225L;
	}

	// Master to data provider workers: Serialized version of the unsolved hashes.
	@Data @NoArgsConstructor @AllArgsConstructor
	static class UnsolvedHashesMessage implements Serializable {
		private static final long serialVersionUID = 8266910043406252422L;
		// can be null if maximum offset was reached. If it is null, the receiver knows that all hashes have been sent.
		private byte[][] hashes;
		private int chunkOffset;
        private long iterationId;
	}

	// Data provider to local workers: Reference version of the unsolved hashes (prevent copy in local ram).
	@Data @NoArgsConstructor @AllArgsConstructor
	static class UnsolvedHashesReferenceMessage implements Serializable {
		private static final long serialVersionUID = 6962155509875752392L;
		private Set<ByteBuffer> hashes;
        private long iterationId;
	}

	// Worker to master: I know what hashes to look for. Give me some work!
	@Data
	static class UnsolvedHashesReceivedMessage implements Serializable {
		private static final long serialVersionUID = 8266910043406252422L;
	}

	// Master to self: Someone wants work. Distribute work.
	@Data
	private static class DistributeWorkPacketsMessage implements Serializable {
		private static final long serialVersionUID = 3327522514637238884L;
	}

	// Worker to master: I found a match for this hash.
	@Data @NoArgsConstructor @AllArgsConstructor
	static class HashSolvedMessage implements Serializable {
		private static final long serialVersionUID = 3443862827428452603L;
		private byte[] hash;
		private String string;
	}

	// Worker to master: I'm done with my current task. Mark the task as done and give me a new one.
	@Data @NoArgsConstructor @AllArgsConstructor
	static class DoneMessage implements Serializable {
		private static final long serialVersionUID = 2476247634500726940L;
        private long iterationId;
	}

	// Master to worker: Try out all combinations based on this alphabet and these fixed chars.
	@Data @NoArgsConstructor @AllArgsConstructor
	static class PasswordWorkPacketMessage implements Serializable {
		private static final long serialVersionUID = 4661499214826867244L;
		// The alphabet. Each char of the PW could be one of these chars
		private Set<Character> alphabet;
		// The length of the password
		private int length;
		// The fixed String that should be used as prefix. Used for further distributing.
		String prefixString;
		// Required so when the DoneMessage comes late, the master knows whether to put the worker back in the idle queue.
        private long iterationId;
	}

	// Master to worker: Try out all permutations of this alphabet, using these fixed chars.
    @Data @NoArgsConstructor @AllArgsConstructor
    static class HintWorkPacketMessage implements Serializable {
        private static final long serialVersionUID = 1147004165303224462L;
        // The alphabet. We want to compute hashes of permutations of this.
        private Set<Character> reducedAlphabet;
        // The fixed string that should be used as prefix. Used for further distributing.
        String prefixString;
        // Required so when the DoneMessage comes late, the master knows whether to put the worker back in the idle queue.
        private long iterationId;
    }


	/////////////////
	// Actor State //
	/////////////////

	@Data @NoArgsConstructor @AllArgsConstructor
	private static class CsvEntry {
		private int id;
		private int unsolved_hints_left;
		// We need this so for a given (String, Hash) pair, we can decide whether this is a solution to a hint or to the
		// password.
		private ByteBuffer passwordHash;
		private Set<Character> reducedPasswordAlphabet;

		void storeHintSolution(String hint) {
			Set<Character> hintSet = hint.chars().mapToObj(e->(char)e).collect(Collectors.toSet());
			reducedPasswordAlphabet.retainAll(hintSet);
			unsolved_hints_left -= 1;
		}
	}

    // Should be either HintWorkPacketMessages or PasswordWorkPacketMessages
    // Will be filled when all csv lines have been read and when all hints for a line have been solved
    private List<Object> openWorkPackets;

	// When a node goes down, we need to redistribute the work of the actors on this node
    // Should be either HintWorkPacketMessages or PasswordWorkPacketMessages
    private Map<ActorRef, Object> currentlyWorkingOn;

    // Maps from ActorRef to the offset in this.unsolvedHashBytes for the chunk to be sent.
	private Map<ActorRef, Integer> actorsWaitingForUnsolvedMessages;
	private Set<ActorRef> actorsWaitingForUnsolvedReferenceMessages;
	// idle means that currently, no work packet is assigned to this worker
	private Set<ActorRef> idleWorkers;

	// required to send UnsolvedHashesReferenceMessages
	private Set<ByteBuffer> unsolvedHashes;
	// required to send UnsolvedHashesMessage - we only want to build this once and reuse it.
	private byte[][][] unsolvedHashBytes;

	// required to find out whether we are done solving hints / solving passwords
	private long unsolvedHintHashes;
	private long unsolvedPasswordHashes;
	private boolean passwordPacketsCreated;

	private long totalHintCount;
	private long totalPasswordCount;

	// For fast lookup when a worker has found the raw string for a hash, we keep this lookup table
	private Map<ByteBuffer, List<CsvEntry> > hashToEntry;

	// These will be kept across iterations, that's why they're initialized here.
	private Set<Character> passwordChars = null;
	private int passwordLength = -1;
	private long iterationId = 0;

	// Are we currently reading the csv file? If so, some internal structures might not be set up completely (unsolvedHashes, ...)
	private boolean reading = false;
	// Does the csvReader have more lines to tell us? If so, we need to get back to reading after solving the current iteration.
	private boolean readerHasLines = true;

	private final ActorRef reader;
	private final ActorRef collector;
	private final List<ActorRef> workers;

	private long startTime;


	/////////////////////
	// Private Methods //
	/////////////////////

	private void addHashEntryPairToEntryLookupMap(ByteBuffer hash, CsvEntry entry) {
		List<CsvEntry> hashToEntryMapEntry = this.hashToEntry.computeIfAbsent(hash, k -> new ArrayList<>());
		hashToEntryMapEntry.add(entry);
	}

	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	@Override
	public void preStart() {
		if (VALIDATE_MEMORY_ESTIMATIONS) {
			this.log().warning("VALIDATE_MEMORY_ESTIMATIONS is set to true. Turn off for benchmarking.");

			Random r = new Random();
			byte[][] array = new byte[HASHES_PER_UNSOLVED_HASHES_MESSAGE][];

			for(int i = 0; i < array.length; ++i) {
				array[i] = new byte[32];
				r.nextBytes(array[i]);
			}

			UnsolvedHashesMessage message = new UnsolvedHashesMessage(array, 0, this.iterationId);

			Kryo kryo = new Kryo();
			kryo.register(UnsolvedHashesMessage.class);
			ByteArrayOutputStream stream = new ByteArrayOutputStream();

			Output output = new Output(stream);
			kryo.writeObject(output, message);
			output.close();

			this.log().info(HASHES_PER_UNSOLVED_HASHES_MESSAGE + " hashes would be sent in " + stream.size() / 1000 + " * 1000 B");
			this.log().info("Maximum message size is set to " + MAXIMUM_MESSAGE_BYTES / 1000 + " * 1000B");
			if (stream.size() >= MAXIMUM_MESSAGE_BYTES) {
				this.log().error("Maximum message size validation failed.");
			} else {
				this.log().info("Maximum message size validation succeeded.");
			}
		}

		long estimated_max_hash_memory_usage = MAXIMUM_HASHES_TO_FIT_IN_MEMORY * ESTIMATED_MEMORY_USAGE_PER_HASH;
		long heapMaxSize = Runtime.getRuntime().maxMemory();
		if (estimated_max_hash_memory_usage > heapMaxSize) {
			this.log().error("MAXIMUM_HASHES_TO_FIT_IN_MEMORY is set too high -- huge input files will trigger OOM exceptions.");
			this.log().error("MAXIMUM_HASHES_TO_FIT_IN_MEMORY: " + MAXIMUM_HASHES_TO_FIT_IN_MEMORY);
			this.log().error("resulting hash size:             " + estimated_max_hash_memory_usage);
			this.log().error("maximum heap size:               " + heapMaxSize);
			this.log().error("To fix OOM exceptions, set an appropriate value for MAXIMUM_HASHES_TO_FIT_IN_MEMORY.");
		}
		else if (estimated_max_hash_memory_usage > heapMaxSize / 2) {
			this.log().warning("MAXIMUM_HASHES_TO_FIT_IN_MEMORY is set to a high value. In case of OOM exceptions, adjust the value.");
			this.log().warning("MAXIMUM_HASHES_TO_FIT_IN_MEMORY: " + MAXIMUM_HASHES_TO_FIT_IN_MEMORY);
			this.log().warning("resulting hash size:             " + estimated_max_hash_memory_usage);
			this.log().warning("maximum heap size:               " + heapMaxSize);
		}

		Reaper.watchWithDefaultReaper(this);
	}

	////////////////////
	// Actor Behavior //
	////////////////////

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(StartMessage.class, this::handle)
				.match(BatchMessage.class, this::handle)

				.match(RegistrationMessage.class, this::handle)

				.match(CreateHintWorkPacketsMessage.class, this::handle)

				.match(SendUnsolvedHashesMessage.class, this::handle)
				.match(SendUnsolvedHashesReferenceMessage.class, this::handle)
				.match(DistributeUnsolvedHashesMessage.class, this::handle)
				.match(UnsolvedHashesReceivedMessage.class, this::handle)

				.match(DistributeWorkPacketsMessage.class, this::handle)
				.match(HashSolvedMessage.class, this::handle)
				.match(DoneMessage.class, this::handle)

				.match(Terminated.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handle(StartMessage message) {
		this.startTime = System.currentTimeMillis();

		this.startReading();
	}

	private void handle(BatchMessage message) {
		assert(this.reading);

		if (message.getLines().isEmpty()) {
			this.processIteration(true);
			return;
		}

		for (String[] line : message.getLines()) {
			int passwordLength = Integer.parseInt(line[3]);
			if (this.passwordLength == -1) {
				this.passwordChars = line[2].chars().mapToObj(e -> (char) e).collect(Collectors.toSet());
				this.passwordLength = passwordLength;
			} else {
				assert(passwordLength == this.passwordLength);
				assert(line[2].chars().mapToObj(e->(char)e).collect(Collectors.toSet()).equals(this.passwordChars));
			}

			CsvEntry entry = new CsvEntry();

			entry.id = Integer.parseInt(line[0]);
			entry.unsolved_hints_left = line.length - 5;
            entry.reducedPasswordAlphabet = new HashSet<>(this.passwordChars);
            entry.passwordHash = HexStringParser.parse(line[4]);

			ByteBuffer[] hintHashes = new ByteBuffer[line.length - 5];
			for (int i = 5; i < line.length; ++i) {
				hintHashes[i - 5] = HexStringParser.parse(line[i]);
			}

			this.addHashEntryPairToEntryLookupMap(entry.passwordHash, entry);

			boolean passwordHashAdded = this.unsolvedHashes.add(entry.passwordHash);
			this.unsolvedPasswordHashes += passwordHashAdded ? 1 : 0;

			this.totalHintCount += entry.unsolved_hints_left;
			this.totalPasswordCount += 1;

			for (ByteBuffer hintHash : hintHashes) {
				this.addHashEntryPairToEntryLookupMap(hintHash, entry);

				boolean hintHashAdded = this.unsolvedHashes.add(hintHash);
				this.unsolvedHintHashes += hintHashAdded ? 1 : 0;
			}
		}

		if (this.unsolvedHashes.size() >= MAXIMUM_HASHES_TO_FIT_IN_MEMORY) {
			this.log().error("");
			this.log().error("The input file has more unique hashes than set in MAXIMUM_HASHES_TO_FIT_IN_MEMORY.");
			this.log().error("The algorithm has to fall back to iterating over smaller chunks of the input.");
			this.log().error("This is much slower than the intended use of doing only one iteration.");
			this.log().error("If more memory is available on the machines, you should increase MAXIMUM_HASHES_TO_FIT_IN_MEMORY.");
			this.log().error("See the README.md");
			this.log().error("");
			this.processIteration(false);
			return;
	 	}

		this.reader.tell(new Reader.ReadMessage(), this.self());
	}

	private void processIteration(boolean readerWasDone) {
		assert(this.reading);

		if (readerWasDone) {
			this.readerHasLines = false;
		}

		this.reading = false;

		if (this.unsolvedHashes.size() != 0) {
			this.self().tell(new DistributeUnsolvedHashesMessage(), this.self());
			this.self().tell(new CreateHintWorkPacketsMessage(), this.self());
		} else {
			this.terminate();
		}
	}

	private void startReading() {
		assert(!this.reading);
		// reset all internal state so that we can start filling it up again when the reader sends batches

		// We can only come here if the current iteration is completely solved.
		this.openWorkPackets = new LinkedList<>();
		this.currentlyWorkingOn = new HashMap<>();

		// Drop any open requests if there are any. We will tell the workers to ask for this again.
		this.actorsWaitingForUnsolvedMessages = new HashMap<>();
		this.actorsWaitingForUnsolvedReferenceMessages = new HashSet<>();

		// Actors will end up here again when they have asked for the unsolved hashes.
		this.idleWorkers = new HashSet<>();

		// Data related to the iteration itself. Clear all so the reader has a fresh base to start from.
		this.unsolvedHintHashes = 0;
		this.unsolvedPasswordHashes = 0;
		this.passwordPacketsCreated = false;
		this.totalHintCount = 0;
		this.totalPasswordCount = 0;
		this.unsolvedHashes = new HashSet<>();
		this.unsolvedHashBytes = null;
		this.hashToEntry = new HashMap<>();

		// Set state back to reading to queue the requests for unsolved hashes until everything is read.
		this.reading = true;
		this.iterationId += 1;

		// Send messages to all workers that they should drop their state (unsolvedHashes, unsolvedHashesReceived)
		// When called from the ctor, this should still be empty. The iterationId is a bit tricky for a newly started system.
		GetUnsolvedHashesMessage msg = new GetUnsolvedHashesMessage(this.iterationId);

		for (ActorRef worker : this.workers) {
			worker.tell(msg, this.self());
		}

		// Tell the reader to start sending batches again.
		this.reader.tell(new Reader.ReadMessage(), this.self());
	}

	private void handle(CreateHintWorkPacketsMessage message) {
		assert(!this.reading);

		// You can also construct cases where it's way more efficient to directly crack the passwords and completely
		// ignore the hints, e.g. when the character set has 15 chars but each password only has length 10.
		// We have 15! possibilities for hints here, but only 15^10 possible passwords. In this case, don't create
		// work packets for the hints, just directly start working on the passwords.
		BigInteger possibleHints = possibleHints(this.passwordChars.size());
		long averageHintsPerPassword = this.totalHintCount / this.totalPasswordCount;
		BigInteger estimatedPossiblePasswordsAfterSolvingHints = estimatePossiblePasswordsAfterSolvingHints(
				this.passwordChars.size(), this.totalPasswordCount, averageHintsPerPassword, this.passwordLength);

		BigInteger computationsWithSolvingHints = possibleHints.add(estimatedPossiblePasswordsAfterSolvingHints);
		BigInteger computationsWithoutSolvingHints = possiblePasswords(this.passwordChars.size(), this.passwordLength);

		if (computationsWithSolvingHints.compareTo(computationsWithoutSolvingHints) > 0) {
			this.log().warning("Input data has such structure that we estimate it to be cheaper to ignore the hints.");
			this.log().warning("-> ignoring hints.");

			// No hints were solved -> all entries have the same unreduced reduced alphabet
			this.createPasswordWorkPacketsForAlphabet(this.passwordChars);
		} else {
			for (char removedChar : this.passwordChars) {
				Set<Character> reducedSet = new HashSet<>(this.passwordChars);
				reducedSet.remove(removedChar);
				this.createHintWorkPacketsRecursively(reducedSet, this.passwordChars.size(), "");
			}
		}

		this.self().tell(new DistributeWorkPacketsMessage(), this.self());
	}

	private void createHintWorkPacketsRecursively(Set<Character> charsLeft, long packetsOnThisRecursionLevel, String prefix) {
		boolean prefixTooLong = charsLeft.size() <= MINIMUM_HINT_PACKET_LENGTH_LEFT;

		boolean enoughWorkPackets = packetsOnThisRecursionLevel >= TARGET_WORK_PACKET_COUNT;
		if (enoughWorkPackets || prefixTooLong) {
			this.openWorkPackets.add(new HintWorkPacketMessage(charsLeft, prefix, this.iterationId));
			return;
		}

		for (char fixedChar : charsLeft) {
			Set<Character> reducedAlphabet = new HashSet<>(charsLeft);
			reducedAlphabet.remove(fixedChar);

			this.createHintWorkPacketsRecursively(reducedAlphabet,
					packetsOnThisRecursionLevel * charsLeft.size(),
					prefix + fixedChar);
		}
	}

	private static BigInteger possibleHints(long charSetSize) {
		// For n chars, there are n possibilities of taking a char away. For each of these possibilities, we are left
		// with (n-1)! permutations. So, we compute n * (n-1)! = n!

		BigInteger result = BigInteger.valueOf(1);
		for (long factor = 2; factor <= charSetSize; factor++) {
			result = result.multiply(BigInteger.valueOf(factor));
		}
		return result;
	}

	private static BigInteger possiblePasswords(long charSetSize, long passwordLength) {
		// For each position in the password, there are charSetSize different possibilities to fill this position
		// So, we compute charSetSize ^ passwordLength

		return BigInteger.valueOf(charSetSize).pow((int) passwordLength);
	}

	private static BigInteger estimatePossiblePasswordsAfterSolvingHints(long charSetSize,
																		 long passwordCount,
																		 long estimatedRemovedCharsPerPassword,
																		 long passwordLength) {
		// Alrighty, so we will get countOfReducedCharSets subsets of the character set, for each set we
		// will have to go through possiblePasswords(reducedCharSetSize, passwordLength) possibilities.
		// For a rough estimation, we assume that on each line we will get exactly estimatedRemovedCharsPerPassword
		// less chars when the hints are solved. Also, we think that we are unlucky and we will get
		// as many different reduced char sets as possible.

		long reducedCharSetSize = charSetSize - estimatedRemovedCharsPerPassword;

		// How many possible subsets of size reducedCharSetSize are there? We can not have more subsets than passwords
		BigInteger countOfReducedCharSets = binomial(charSetSize, reducedCharSetSize).min(BigInteger.valueOf(passwordCount));

		return countOfReducedCharSets.multiply(possiblePasswords(reducedCharSetSize, passwordLength));
	}

	// https://stackoverflow.com/questions/2201113/combinatoric-n-choose-r-in-java-math
	private static BigInteger binomial(final long N, final long K) {
		BigInteger ret = BigInteger.ONE;
		for (int k = 0; k < K; k++) {
			ret = ret.multiply(BigInteger.valueOf(N-k))
					.divide(BigInteger.valueOf(k+1));
		}
		return ret;
	}

	private void handle(DistributeWorkPacketsMessage message) {
		assert(!this.reading);

		Iterator<Object> workPacketIterator = this.openWorkPackets.iterator();
		Iterator<ActorRef> actorIterator = this.idleWorkers.iterator();

		while (workPacketIterator.hasNext() && actorIterator.hasNext()) {
			Object workPacket = workPacketIterator.next();
            workPacketIterator.remove();

			ActorRef actor = actorIterator.next();
			actorIterator.remove();

			this.tellWorkPacket(actor, workPacket);
		}
	}

	private void tellWorkPacket(ActorRef actor, Object workPacket) {
	    assert(workPacket instanceof HintWorkPacketMessage || workPacket instanceof PasswordWorkPacketMessage);

		if (workPacket instanceof HintWorkPacketMessage) {
			if (this.unsolvedHintHashes == 0) {
				if (LOG_PROGRESS)
					this.log().info("Dropped Hint packet as all hints are solved");
				return;
			}
		} else {
			if (this.unsolvedPasswordHashes == 0) {
				if (LOG_PROGRESS)
					this.log().info("Dropped Password packet as all passwords are solved");
				return;
			}
		}

		actor.tell(workPacket, this.self());
		Object previousValue = this.currentlyWorkingOn.put(actor, workPacket);
		assert(previousValue == null);
	}

	private void handle(UnsolvedHashesReceivedMessage message) {
		assert(!this.reading);

		this.idleWorkers.add(this.sender());
		this.self().tell(new DistributeWorkPacketsMessage(), this.self());
	}

	private void handle(DoneMessage message) {
        // It may happen that we receive DoneMessages from a previous iteration because some actor was still going through
        // their task. In this case, we must not put the actors back in the idle queue as they may have not yet received
        // the new hashes we're searching for. Thus, we ignore the message in this case.
        if(message.getIterationId() != this.iterationId) {
            return;
        }

		this.currentlyWorkingOn.remove(this.sender());
		this.idleWorkers.add(this.sender());
		this.self().tell(new DistributeWorkPacketsMessage(), this.self());
	}

	private void handle(HashSolvedMessage message) {
		assert(!this.reading);

		ByteBuffer wrappedHash = wrap(message.getHash());

		List<CsvEntry> entryList = this.hashToEntry.get(wrappedHash);
		assert(entryList != null);
		assert(entryList.size() > 0);

		for (CsvEntry entry : entryList) {
			if (wrappedHash.equals(entry.passwordHash)) {
				this.passwordSolved(entry, wrappedHash, message.getString());
			} else {
				this.hintSolved(entry, wrappedHash, message.getString());
			}
		}

		if (this.unsolvedHintHashes == 0 && !this.passwordPacketsCreated) {
			this.createPasswordWorkPackets();
		}

		if (this.unsolvedPasswordHashes == 0) {
			if (this.readerHasLines) {
				this.startReading();
			} else {
				this.terminate();
			}
		}
	}

	private void createPasswordWorkPackets() {
		Set<Set<Character>> uniqueAlphabets = new HashSet<>();
		int maxAlphabetSize = 0;

		for (Iterable<CsvEntry> entryList : this.hashToEntry.values()) {
			for (CsvEntry entry : entryList) {
				uniqueAlphabets.add(entry.reducedPasswordAlphabet);
				maxAlphabetSize = Math.max(maxAlphabetSize, entry.reducedPasswordAlphabet.size());
			}
		}

		if (CHECK_PASSWORD_ALPHABETS_FOR_SUBSETS) {
			if (uniqueAlphabets.size() > 10000) {
				this.log().warning("The input file results in a lot of unique password alphabets. I will try to " +
						"deduplicate work by making sure that no password alphabet is contained within another alphabet. " +
						"However, this requires O(n^2) operations with n = " + uniqueAlphabets.size() + " for the current " +
						"input file. If it does not happen very often in the input file that a password's reduced alphabet " +
						"is a subset of another password's reduced alphabet, make sure to turn off " +
						"CHECK_PASSWORD_ALPHABETS_FOR_SUBSETS.");
			}
			this.log().info("Starting password alphabet subset deduplication...");
			long setsRemoved = 0;

			ArrayList<LinkedList<Set<Character>>> alphabetsWithSize = new ArrayList<>(maxAlphabetSize + 1);
			for (int size = 0; size < maxAlphabetSize + 1; ++size)
				alphabetsWithSize.add(new LinkedList<>());

			for (Set<Character> reducedAlphabet : uniqueAlphabets) {
				alphabetsWithSize.get(reducedAlphabet.size()).add(reducedAlphabet);
			}

			// This looks intimidating, it is "only" n^2 on the count of unique sets though.
			// We think it's better to spend some time here than to recheck the same character sets.
			// However, if you are sure that no cases will occur where one password's reduced character set is contained
			// in another passwords character set, you can set
			for(int currentSize = maxAlphabetSize; currentSize > 0; --currentSize) {
				for (int smallerSize = currentSize - 1; smallerSize > 0; --smallerSize) {
					for(Set<Character> currentSet : alphabetsWithSize.get(currentSize)) {
						Iterator<Set<Character>> smallerSetIterator = alphabetsWithSize.get(smallerSize).iterator();
						while(smallerSetIterator.hasNext()) {
							Set<Character> smallerSet = smallerSetIterator.next();
							if (currentSet.containsAll(smallerSet)) {
								smallerSetIterator.remove();
								uniqueAlphabets.remove(smallerSet);
								setsRemoved += 1;
							}
						}
					}
				}
			}

			this.log().warning("Done. I removed " + setsRemoved + " alphabets.");
		} else {
			this.log().warning("You have turned off CHECK_PASSWORD_ALPHABETS_FOR_SUBSETS. If a significant count of " +
					"reduced password alphabets are subsets of other reduced password alphabets, you might experience" +
					"degraded performance.");
		}

		for (Set<Character> uniqueAlphabet : uniqueAlphabets) {
			this.createPasswordWorkPacketsForAlphabet(uniqueAlphabet);
		}

		this.passwordPacketsCreated = true;
		this.self().tell(new DistributeWorkPacketsMessage(), this.self());
	}

	private void hintSolved(CsvEntry entry, ByteBuffer hash, String hint) {
		this.unsolvedHintHashes -= 1;
		entry.storeHintSolution(hint);

		// We decided _not_ to start cracking the password before we have solved all hints, here's why:
		// For a single line, let cracking another hint take time t1, cracking the PW directly take t2 and
		// cracking the password after cracking the next hint t3. It is true that in some cases, t1 + t3 > t2.
		// But, we are dealing with many password lines, so while searching through the unsearched hints
		// (spending t1), we will not only find remaining hint values for this line, but with a very high
		// probability also for other hints. Assuming that there will be a lot of distinct resulting character sets,
		// computing the PWs will be faster since for most lines we find an additional hint for, we reduce the time from
		// t2 to t3. Thus, we need to compare t1 + n * t3, and this is with high probability less than n * t2.
		if (LOG_PROGRESS) {
			this.log().info("Hint solved, " + this.unsolvedHintHashes + " to do.");
		}
	}

	private void createPasswordWorkPacketsForAlphabet(Set<Character> alphabet) {
		this.createPasswordWorkPacketsRecursively(alphabet,
			1,
			""
		);
	}

	private void createPasswordWorkPacketsRecursively(Set<Character> passwordChars, long packetsOnThisRecursionLevel, String prefix) {
		boolean prefixTooLong = this.passwordLength - prefix.length() <= MINIMUM_PASSWORD_PACKET_LENGTH_LEFT;
		boolean enoughWorkPackets = packetsOnThisRecursionLevel >= TARGET_WORK_PACKET_COUNT;

		if (enoughWorkPackets || prefixTooLong) {
			this.openWorkPackets.add(
				new PasswordWorkPacketMessage(passwordChars, this.passwordLength, prefix, this.iterationId)
			);
			return;
		}

		for (char fixedChar : passwordChars) {
			this.createPasswordWorkPacketsRecursively(
				passwordChars,
				packetsOnThisRecursionLevel * passwordChars.size(),
				prefix + fixedChar
			);
		}
	}

	private void passwordSolved(CsvEntry entry, ByteBuffer hash, String password) {
		this.collector.tell(new Collector.CollectMessage(entry.id + ": " + password), this.self());

		this.unsolvedPasswordHashes -= 1;

		if (LOG_PROGRESS) {
			this.log().info("Password solved, " + this.unsolvedPasswordHashes + " to do.");
		}
	}

	private void handle(RegistrationMessage message) {
		this.context().watch(this.sender());
		this.workers.add(this.sender());
		this.log().info("Registered {}", this.sender());
	}

	private void handle(SendUnsolvedHashesMessage message) {
	    if (message.getIterationId() != this.iterationId) {
			assert(message.getIterationId() < this.iterationId);
			this.sender().tell(new GetUnsolvedHashesMessage(this.iterationId), this.self());
            return;
        }

		this.actorsWaitingForUnsolvedMessages.put(this.sender(), message.getChunkOffset());
		this.self().tell(new DistributeUnsolvedHashesMessage(), this.self());
	}

	private void handle(SendUnsolvedHashesReferenceMessage message) {
		if (message.getIterationId() != this.iterationId) {
			assert(message.getIterationId() < this.iterationId);
			this.sender().tell(new GetUnsolvedHashesMessage(this.iterationId), this.self());
			return;
		}

		this.actorsWaitingForUnsolvedReferenceMessages.add(this.sender());
		this.self().tell(new DistributeUnsolvedHashesMessage(), this.self());
	}

	private void handle(DistributeUnsolvedHashesMessage message) {
		// If we're still reading, data might be unfinished. Handle later.
		if (this.reading) {
			return;
		}

		// Lazily build a chunked representation of the hashes for sending
		if (this.unsolvedHashBytes == null) {
			int unsolvedHashes = this.unsolvedHashes.size();
			int unsolvedHashesLeft = unsolvedHashes;
			int chunk_count = (int) Math.ceil((double)unsolvedHashes / HASHES_PER_UNSOLVED_HASHES_MESSAGE);
			this.unsolvedHashBytes = new byte[chunk_count][][];

			int chunk_id = 0;
			int offset_inside_chunk = 0;
			for (ByteBuffer hash : this.unsolvedHashes) {
				assert(offset_inside_chunk <= HASHES_PER_UNSOLVED_HASHES_MESSAGE);

				if (offset_inside_chunk == HASHES_PER_UNSOLVED_HASHES_MESSAGE) {
					offset_inside_chunk = 0;
					chunk_id++;
					unsolvedHashesLeft -= HASHES_PER_UNSOLVED_HASHES_MESSAGE;
				}
				assert(chunk_id < chunk_count);

				if (offset_inside_chunk == 0) {
					int chunk_size = Math.min(HASHES_PER_UNSOLVED_HASHES_MESSAGE, unsolvedHashesLeft);
					this.unsolvedHashBytes[chunk_id] = new byte[chunk_size][];
				}

				this.unsolvedHashBytes[chunk_id][offset_inside_chunk++] = hash.array();
			}
		}

		for (Map.Entry<ActorRef, Integer> entry : this.actorsWaitingForUnsolvedMessages.entrySet()) {
			ActorRef actor = entry.getKey();
			ActorSelection largeMessageForwarder = this.context().actorSelection(actor.path().child(LargeMessageForwarder.DEFAULT_NAME));
			int chunk_offset = entry.getValue();

			if (chunk_offset >= this.unsolvedHashBytes.length) {
				largeMessageForwarder.tell(new UnsolvedHashesMessage(null, chunk_offset, this.iterationId), this.self());
			} else {
				largeMessageForwarder.tell(
				    new UnsolvedHashesMessage(
				       this.unsolvedHashBytes[chunk_offset], chunk_offset, this.iterationId
                    ), this.self()
                );
			}
		}
		this.actorsWaitingForUnsolvedMessages.clear();

		UnsolvedHashesReferenceMessage referenceMessage = new UnsolvedHashesReferenceMessage(
		        this.unsolvedHashes, this.iterationId
        );

		for (ActorRef actor : this.actorsWaitingForUnsolvedReferenceMessages) {
			actor.tell(referenceMessage, this.self());
		}
		this.actorsWaitingForUnsolvedReferenceMessages.clear();
	}

	private void handle(Terminated message) {
		this.context().unwatch(message.getActor());
		this.workers.remove(message.getActor());
		this.idleWorkers.remove(message.getActor());

		Object lostWork = this.currentlyWorkingOn.remove(message.getActor());
		if(lostWork != null){
			this.openWorkPackets.add(lostWork);
			this.self().tell(new DistributeWorkPacketsMessage(), this.self());
		}

		this.log().info("Unregistered {}", message.getActor());
	}

	private void terminate() {
		assert(!this.reading);

		this.collector.tell(new Collector.PrintMessage(), this.self());
		this.reader.tell(PoisonPill.getInstance(), ActorRef.noSender());
		this.collector.tell(PoisonPill.getInstance(), ActorRef.noSender());

		for (ActorRef worker : this.workers) {
			this.context().unwatch(worker);
			worker.tell(PoisonPill.getInstance(), ActorRef.noSender());
		}

		this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());

		long executionTime = System.currentTimeMillis() - this.startTime;
		this.log().info("Algorithm finished in {} ms", executionTime);
	}
}
