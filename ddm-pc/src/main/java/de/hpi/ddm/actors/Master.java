package de.hpi.ddm.actors;

import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.actor.Terminated;
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
	public static final boolean LOG_PROGRESS = true;

	// ---- Assumptions on the limitations of large messages
	public static final boolean VALIDATE_MEMORY_ESTIMATIONS = true;

	// If not using the large message channel, the maximum frame size should be 128kB
	// TODO: This should probably use the large message channel, maybe even with a cranked up maximum-large-frame-size
	//   https://doc.akka.io/docs/akka/2.5.4/scala/general/configuration.html
	//   4 MB should be okay then.
	public static final int MAXIMUM_MESSAGE_BYTES = 128000;
	// 32kB were measured on a huge message (4 * 1024 * 1024 Hashes = 136MB of serialized data).
	// For smaller messages, it's usually less
	public static final int UNSOLVED_HASHES_MESSAGE_OVERHEAD = 32 * 1024;
	public static final int REQUIRED_SPACE_PER_STORED_HASH = 34; // Bytes, measured.
	public static final int HASHES_PER_UNSOLVED_HASHES_MESSAGE =
			(MAXIMUM_MESSAGE_BYTES - UNSOLVED_HASHES_MESSAGE_OVERHEAD) / REQUIRED_SPACE_PER_STORED_HASH;


	public static Props props(final ActorRef reader, final ActorRef collector) {
		return Props.create(Master.class, () -> new Master(reader, collector));
	}

	private Master(final ActorRef reader, final ActorRef collector) {
		this.reader = reader;
		this.collector = collector;
		this.workers = new ArrayList<>();
	}

	////////////////////
	// Actor Messages //
	////////////////////

	@Data
	public static class StartMessage implements Serializable {
		private static final long serialVersionUID = -50374816448627600L;
	}
	
	@Data @NoArgsConstructor @AllArgsConstructor
	static class BatchMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private List<String[]> lines;
	}

	@Data
	static class RegistrationMessage implements Serializable {
		private static final long serialVersionUID = 3303081601659723997L;
	}

	@Data
	private static class CreateHintWorkPacketsMessage implements Serializable {
		private static final long serialVersionUID = 4016375330343989553L;
	}

	@Data
	private static class CreatePasswordWorkPackets implements Serializable {
		private static final long serialVersionUID = 5729686774061377664L;
	}

	@Data
	public static class SendUnsolvedHashesMessage implements Serializable {
		private static final long serialVersionUID = 8996201587099482364L;
	}

	@Data
	public static class SendUnsolvedHashesReferenceMessage implements Serializable {
		private static final long serialVersionUID = 7887543928732622009L;
	}

	@Data
	static class DistributeUnsolvedHashesMessage implements Serializable {
		private static final long serialVersionUID = 5705955020161158225L;
	}

	// TODO (later): Don't sent both at the same time - we only need the hint hashes in the first phase
	//  and the password hashes in the second phase -- this goes along with using Akka Distributed Data for the syncing.
	// TODO: Unify to single list -- distinguishing between hint and pw hashes should not be necessary
	@Data @NoArgsConstructor @AllArgsConstructor
	static class UnsolvedHashesMessage implements Serializable {
		private static final long serialVersionUID = 8266910043406252422L;
		private byte[][] hintHashes;
		private byte[][] passwordHashes;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	static class UnsolvedHashesReferenceMessage implements Serializable {
		private static final long serialVersionUID = 6962155509875752392L;
		private Set<ByteBuffer> hintHashes;
		private Set<ByteBuffer> passwordHashes;
	}

	@Data
	static class UnsolvedHashesReceivedMessage implements Serializable {
		private static final long serialVersionUID = 8266910043406252422L;
	}

	@Data
	private static class DistributeWorkPacketsMessage implements Serializable {
		private static final long serialVersionUID = 3327522514637238884L;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	static class HintSolvedMessage implements Serializable {
		private static final long serialVersionUID = 3443862827428452603L;
		private byte[] hash;
		private String hint;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class PasswordSolvedMessage implements Serializable {
		private static final long serialVersionUID = 5219945881030570315L;
		private byte[] hash;
		private String password;
	}

	@Data
	static class DoneMessage implements Serializable {
		private static final long serialVersionUID = 2476247634500726940L;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	static class PasswordWorkPacketMessage implements Serializable {
		private static final long serialVersionUID = 4661499214826867244L;
		// The alphabet. Each char of the PW could be one of these chars
		private Set<Character> alphabet;
		// The length of the password
		private int length;
		// The fixed character that should be used as prefix. Used for further distributing.
		char prefixChar;
	}

    @Data @NoArgsConstructor @AllArgsConstructor
    static class HintWorkPacketMessage implements Serializable {
        private static final long serialVersionUID = 1147004165303224462L;
        // The alphabet. We want to compute hashes of permutations of this.
        private Set<Character> reducedAlphabet;
        // The fixed character that should be used as prefix. Used for further distributing.
        char prefixChar;
    }

	
	/////////////////
	// Actor State //
	/////////////////


	// Structures to internally keep track of solved and unsolved tasks

	@Data @NoArgsConstructor @AllArgsConstructor
	private static class CsvEntry {
		private int id;
		private String name;
		private Set<Character> reducedPasswordAlphabet;

		public void storeHintSolution(ByteBuffer hintHash, String hint) {
			Set<Character> hintSet = hint.chars().mapToObj(e->(char)e).collect(Collectors.toSet());
			reducedPasswordAlphabet.retainAll(hintSet);
		}
	}
    // Should be either HintWorkPacketMessages or PasswordWorkPacketMessages
    // Will be filled when all csv lines have been read and when all hints have been solved
	// TODO: Replace this with Set for a run and check that no duplicates are in there?
    private List<Object> openWorkPackets = new LinkedList<>();

	// When a node goes down, we need to redistribute the work of the actors on this node
    // Should be either HintWorkPacketMessages or PasswordWorkPacketMessages
    private Map<ActorRef, Object> currentlyWorkingOn = new HashMap<>();

	private Set<ActorRef> actorsWaitingForUnsolvedMessages = new HashSet<>();
	private Set<ActorRef> actorsWaitingForUnsolvedReferenceMessages = new HashSet<>();
	// idle means that currently, no work packet is assigned to this worker
	private Set<ActorRef> idleWorkers = new HashSet<>();

	// To be distributed to new actors before they can start working
	// TODO Später: Eventuell kann dieses Set nicht in einer Nachricht geschickt werden -> Akka Distributed Data
	private Set<ByteBuffer> unsolvedHintHashes = new HashSet<>();  // Needed only in the first phase
	private Set<ByteBuffer> unsolvedPasswordHashes = new HashSet<>();  // Needed only in the second phase

	private ArrayList<CsvEntry> csvEntries = new ArrayList<>();

	// For fast lookup when a worker has found the raw string for a hash, we keep this lookup table
	private Map<ByteBuffer, List<CsvEntry> > hashToEntry = new HashMap<>();

	private Set<Character> passwordChars = null;
	private int passwordLength = -1;

	// Are we done reading the csv file (-> can we start computing hashes on the workers?)
	private boolean readingDone = false;

	private final ActorRef reader;
	private final ActorRef collector;
	// TODO: Do we need this?
	private final List<ActorRef> workers;

	private long startTime;


	/////////////////////
	// Private Methods //
	/////////////////////

	protected void addHashEntryPairToEntryLookupMap(ByteBuffer hash, CsvEntry entry) {
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
			byte[][] dummy = new byte[1][];
			byte[][] array = new byte[HASHES_PER_UNSOLVED_HASHES_MESSAGE][];

			for(int i = 0; i < array.length; ++i) {
				array[i] = new byte[32];
				r.nextBytes(array[i]);
			}

			UnsolvedHashesMessage message = new UnsolvedHashesMessage(array, dummy);

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
				.match(DoneMessage.class, this::handle)
				.match(DistributeUnsolvedHashesMessage.class, this::handle)
				.match(DistributeWorkPacketsMessage.class, this::handle)
				.match(UnsolvedHashesReceivedMessage.class, this::handle)
				.match(HintSolvedMessage.class, this::handle)
				.match(CreatePasswordWorkPackets.class, this::handle)
				.match(PasswordSolvedMessage.class, this::handle)
				.match(Terminated.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	protected void handle(StartMessage message) {
		this.startTime = System.currentTimeMillis();
		
		this.reader.tell(new Reader.ReadMessage(), this.self());
	}

	protected void handle(BatchMessage message) {
		if (message.getLines().isEmpty()) {
			this.readingDone = true;
			this.self().tell(new DistributeUnsolvedHashesMessage(), this.self());
			this.self().tell(new CreateHintWorkPacketsMessage(), this.self());
			return;
		}

		// tell reader to continue reading before we start computing so when we are done, the next message is ready
		this.reader.tell(new Reader.ReadMessage(), this.self());

		for (String[] line : message.getLines()) {
			int passwordLength = Integer.parseInt(line[3]);
			if (this.passwordLength == -1) {
				this.passwordChars = line[2].chars().mapToObj(e->(char)e).collect(Collectors.toSet());
				this.passwordLength = passwordLength;
			} else {
				assert(passwordLength == this.passwordLength);
				assert(line[2].chars().mapToObj(e->(char)e).collect(Collectors.toSet()).equals(this.passwordChars));
			}

			CsvEntry entry = new CsvEntry();
			this.csvEntries.add(entry);

			entry.id = Integer.parseInt(line[0]);
			entry.name = line[1];
            entry.reducedPasswordAlphabet = new HashSet<>(this.passwordChars);

			ByteBuffer passwordHash = HexStringParser.parse(line[4]);
			ByteBuffer[] hintHashes = new ByteBuffer[line.length - 5];
			for (int i = 5; i < line.length; ++i) {
				hintHashes[i - 5] = HexStringParser.parse(line[i]);
			}

			this.addHashEntryPairToEntryLookupMap(passwordHash, entry);
			this.unsolvedPasswordHashes.add(passwordHash);

			for (int i = 0; i < hintHashes.length; ++i) {
				this.addHashEntryPairToEntryLookupMap(hintHashes[i], entry);
				this.unsolvedHintHashes.add(hintHashes[i]);
			}
		}
	}

	protected void handle(CreateHintWorkPacketsMessage message) {
		for (char c : this.passwordChars) {
		    Set<Character> reducedAlphabet = new HashSet<>(this.passwordChars);
            reducedAlphabet.remove(c);

		    for (char fixedChar : reducedAlphabet) {
                this.openWorkPackets.add(new HintWorkPacketMessage(reducedAlphabet, fixedChar));
            }
		}

		this.self().tell(new DistributeWorkPacketsMessage(), this.self());
	}

	protected void handle(DistributeWorkPacketsMessage message) {
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

	protected void handle(UnsolvedHashesReceivedMessage message) {
		this.idleWorkers.add(this.sender());

		// If this leads to message spam / dropped letters, we can implement an own mailbox that makes sure that
		// for some messages (e.g. the DistributeWorkPacketsMessage), only one instance will be kept in the mailbox.
		this.self().tell(new DistributeWorkPacketsMessage(), this.self());
	}

	protected void handle(DoneMessage message) {
		this.currentlyWorkingOn.remove(this.sender());
		this.idleWorkers.add(this.sender());
		this.self().tell(new DistributeWorkPacketsMessage(), this.self());
	}

	protected void handle(HintSolvedMessage message) {
		ByteBuffer wrappedHash = wrap(message.getHash());

		this.unsolvedHintHashes.remove(wrappedHash);

		List<CsvEntry> entryList = this.hashToEntry.get(wrappedHash);
		assert(entryList != null);
		assert(entryList.size() > 0);

		for (CsvEntry entry : entryList) {
			entry.storeHintSolution(wrappedHash, message.getHint());
		}

		// TODO: If all enough hashes are solved, start giving out password tasks
		//  This is the case for all lines where we have solved all hints and where we are sure that for all lines where
		//  unsolved hints are left, we have at least one char that is not contained in the reduced alphabet of this line
		//  anymore.
		if (this.unsolvedHintHashes.isEmpty()) {
			this.self().tell(new CreatePasswordWorkPackets(), this.self());
		}

		if (LOG_PROGRESS) {
			this.log().info("Hint solved, " + this.unsolvedHintHashes.size() + " to do.");
		}
	}

	protected void handle(CreatePasswordWorkPackets message) {
		Set<Set<Character>> uniqueAlphabets = new HashSet<>();
		for (CsvEntry entry : this.csvEntries) {
			uniqueAlphabets.add(entry.reducedPasswordAlphabet);
		}

		for (Set<Character> uniqueAlphabet : uniqueAlphabets) {
            for (char fixedChar : uniqueAlphabet) {
                this.openWorkPackets.add(new PasswordWorkPacketMessage(uniqueAlphabet, this.passwordLength, fixedChar));
            }
		}

		this.self().tell(new DistributeWorkPacketsMessage(), this.self());
	}

	protected void handle(PasswordSolvedMessage message) {
		ByteBuffer wrappedHash = wrap(message.getHash());

		this.unsolvedPasswordHashes.remove(wrappedHash);

		for (CsvEntry entry : this.hashToEntry.get(wrappedHash)) {
			this.collector.tell(new Collector.CollectMessage(entry.id + ": " + message.getPassword()), this.self());
		}

		if (this.unsolvedPasswordHashes.isEmpty()) {
			this.collector.tell(new Collector.PrintMessage(), this.self());
			this.terminate();
		}

		if (LOG_PROGRESS) {
			this.log().info("Password solved, " + this.unsolvedPasswordHashes.size() + " to do.");
		}
	}

	protected void handle(RegistrationMessage message) {
		this.context().watch(this.sender());
		this.workers.add(this.sender());
		this.log().info("Registered {}", this.sender());
	}

	protected void handle(SendUnsolvedHashesMessage message) {
		this.actorsWaitingForUnsolvedMessages.add(this.sender());
		this.self().tell(new DistributeUnsolvedHashesMessage(), this.self());
	}

	protected void handle(SendUnsolvedHashesReferenceMessage message) {
		this.actorsWaitingForUnsolvedReferenceMessages.add(this.sender());
		this.self().tell(new DistributeUnsolvedHashesMessage(), this.self());
	}

	protected void handle(DistributeUnsolvedHashesMessage message) {
		// TODO: Versioning, multiple iterations
		if (!this.readingDone) {
			return;
		}

		// TODO: Cache the byte representation? --> We need more complex sharing logic anyway.
		byte[][] hintHashes = new byte[this.unsolvedHintHashes.size()][];
		int i = 0;
		for (ByteBuffer hintHash : this.unsolvedHintHashes) {
			hintHashes[i++] = hintHash.array();
		}

		byte[][] passwordHashes = new byte[this.unsolvedPasswordHashes.size()][];
		i = 0;
		for (ByteBuffer passwordHash : this.unsolvedPasswordHashes) {
			passwordHashes[i++] = passwordHash.array();
		}
		UnsolvedHashesMessage msg = new UnsolvedHashesMessage(hintHashes, passwordHashes);

		// TODO: What happens if the hashes are too big for one message here?)
		for (ActorRef actor : this.actorsWaitingForUnsolvedMessages) {
			actor.tell(msg, this.self());
		}
		this.actorsWaitingForUnsolvedMessages.clear();

		UnsolvedHashesReferenceMessage referenceMessage = new UnsolvedHashesReferenceMessage(
				this.unsolvedHintHashes, this.unsolvedPasswordHashes);
		for (ActorRef actor : this.actorsWaitingForUnsolvedReferenceMessages) {
			actor.tell(referenceMessage, this.self());
		}
		this.actorsWaitingForUnsolvedReferenceMessages.clear();
	}
	
	protected void handle(Terminated message) {
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

	protected void tellWorkPacket(ActorRef actor, Object workPacket) {
	    if (workPacket instanceof HintWorkPacketMessage) {
            if (this.unsolvedHintHashes.isEmpty()) {
				this.log().info("Dropped Hint packet as all hints are solved");
                return;
            }
        } else if (workPacket instanceof PasswordWorkPacketMessage) {
            if (this.unsolvedPasswordHashes.isEmpty()) {
				this.log().info("Dropped Password packet as all hints are solved");
                return;
            }
        }

	    actor.tell(workPacket, this.self());
        Object previousValue = this.currentlyWorkingOn.put(actor, workPacket);
        assert(previousValue == null);
    }

	protected void terminate() {
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
