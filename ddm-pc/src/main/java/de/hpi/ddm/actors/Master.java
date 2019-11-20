package de.hpi.ddm.actors;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.actor.Terminated;
import de.hpi.ddm.structures.HexStringParser;
import lombok.Data;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

public class Master extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////
	
	public static final String DEFAULT_NAME = "master";

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
	private static class InitializeWorkersMessage implements Serializable {
		private static final long serialVersionUID = 5705955020161158225L;
	}

	// TODO (later): Don't sent both at the same time - we only need the hint hashes in the first phase
	//  and the password hashes in the second phase -- this goes along with using Akka Distributed Data for the syncing.
	@Data @NoArgsConstructor @AllArgsConstructor
	static class UnsolvedHashesMessage implements Serializable {
		private static final long serialVersionUID = 8266910043406252422L;
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
		private ByteBuffer hash;
		private String hint;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class PasswordSolvedMessage implements Serializable {
		private static final long serialVersionUID = 5219945881030570315L;
		private ByteBuffer hash;
		private String password;
	}

	@Data
	static class DoneMessage implements Serializable {
		private static final long serialVersionUID = 2476247634500726940L;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	static class PasswordWorkPacketMessage implements Serializable {
		private static final long serialVersionUID = 4661499214826867244L;
		private Set<Character> alphabet;
		private int length;
		// TODO später: char startChar;
	}

    @Data @NoArgsConstructor @AllArgsConstructor
    static class HintWorkPacketMessage implements Serializable {
        private static final long serialVersionUID = 1147004165303224462L;
        private Set<Character> alphabet;
        private char missingChar;
        // TODO Später: char startChar; // für die Permutation
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
    private List<Object> openWorkPackets = new LinkedList<>();

	// When a node goes down, we need to redistribute the work of the actors on this node
    // Should be either HintWorkPacketMessages or PasswordWorkPacketMessages
    private Map<ActorRef, Object> currentlyWorkingOn = new HashMap<>();

	// uninitialized means has not got information about the hashes we are searching yet
	private List<ActorRef> uninitializedWorkers = new LinkedList<>();
	// idle means that currently, no work packet is assigned to this worker
	private List<ActorRef> idleWorkers = new LinkedList<>();

	// To be distributed to new actors before they can start working
	// TODO Später: Eventuell kann dieses Set nicht in einer Nachricht geschickt werden -> Akka Distributed Data
	private Set<ByteBuffer> unsolvedHintHashes = new HashSet<>();  // Needed only in the first phase
	private Set<ByteBuffer> unsolvedPasswordHashes = new HashSet<>();  // Needed only in the second phase

	// TODO Später: Dynamische Verteilung bei gelösten hashes, damit alle anderen Knoten diesen hash nicht mehr prüfen
	//   --> Distributed Data

	private ArrayList<CsvEntry> csvEntries = new ArrayList<>();

	// For fast lookup when a worker has found the raw string for a hash, we keep this lookup table
	private Map<ByteBuffer, List<CsvEntry> > hashToEntry = new HashMap<>();

	private Set<Character> passwordChars = null;
	private int passwordLength = -1;

	// Are we done reading the csv file (-> can we start computing hashes on the workers?)
	private boolean readingDone = false;

	private final ActorRef reader;
	private final ActorRef collector;
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
				.match(InitializeWorkersMessage.class, this::handle)
				.match(DoneMessage.class, this::handle)
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
			this.self().tell(new InitializeWorkersMessage(), this.self());
			this.self().tell(new CreateHintWorkPacketsMessage(), this.self());

			this.readingDone = true;
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
		// TODO: Improve: Distribute using a fixed first character for each packet.
		for (char c : this.passwordChars) {
			this.openWorkPackets.add(new HintWorkPacketMessage(this.passwordChars, c));
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
			this.currentlyWorkingOn.put(actor, workPacket);
		}
	}

	protected void handle(InitializeWorkersMessage message) {
		// TODO: Böse: die Member sind nicht konstant - set differenz hier bestimmen und eine Kopie erstellen?
        // --> Will be solved with Akka Distributed Data
		UnsolvedHashesMessage msg = new UnsolvedHashesMessage(this.unsolvedHintHashes, this.unsolvedPasswordHashes);

		for (ActorRef worker : this.uninitializedWorkers) {
			// TODO: What happens if the hashes are too big for one message here?) --> Use Akka Distributed Data
			worker.tell(msg, this.self());
		}
	}

	protected void handle(UnsolvedHashesReceivedMessage message) {
		this.uninitializedWorkers.remove(this.sender());
		this.idleWorkers.add(this.sender());

		// TODO: If this leads to message spam / dropped letters, we can implement an own mailbox that makes sure that
		//  for some messages (e.g. the DistributeWorkPacketsMessage), only one instance will be kept in the mailbox.
		this.self().tell(new DistributeWorkPacketsMessage(), this.self());
	}

	protected void handle(DoneMessage message) {
		this.currentlyWorkingOn.remove(this.sender());
		this.idleWorkers.add(this.sender());
		this.self().tell(new DistributeWorkPacketsMessage(), this.self());
	}

	protected void handle(HintSolvedMessage message) {
		// TODO: Propagate to all workers that this hint hash is solved
		this.unsolvedHintHashes.remove(message.getHash());

		List<CsvEntry> entryList = this.hashToEntry.get(message.getHash());
		assert(entryList != null);
		assert(entryList.size() > 0);

		for (CsvEntry entry : entryList) {
			entry.storeHintSolution(message.getHash(), message.getHint());
		}

		// TODO: If all enough hashes are solved, start giving out password tasks
		//  This is the case for all lines where we have solved all hints and where we are sure that for all lines where
		//  unsolved hints are left, we have at least one char that is not contained in the reduced alphabet of this line
		//  anymore.
		if (this.unsolvedHintHashes.isEmpty()) {
			this.self().tell(new CreatePasswordWorkPackets(), this.self());
		}
	}

	protected void handle(CreatePasswordWorkPackets message) {
		Set<Set<Character>> uniqueAlphabets = new HashSet<>();
		for (CsvEntry entry : this.csvEntries) {
			uniqueAlphabets.add(entry.reducedPasswordAlphabet);
		}

		// TODO: Improve: Distribute using a fixed first character for each packet.
		for (Set<Character> uniqueAlphabet : uniqueAlphabets) {
			this.openWorkPackets.add(new PasswordWorkPacketMessage(uniqueAlphabet, this.passwordLength));
		}

		this.self().tell(new DistributeWorkPacketsMessage(), this.self());
	}

	protected void handle(PasswordSolvedMessage message) {
		// TODO: Propagate to all workers that this hint hash is solved
		this.unsolvedPasswordHashes.remove(message.getHash());

		for (CsvEntry entry : this.hashToEntry.get(message.getHash())) {
			this.collector.tell(new Collector.CollectMessage(entry.id + ": " + message.getPassword()), this.self());
		}

		if (this.unsolvedPasswordHashes.isEmpty()) {
			this.collector.tell(new Collector.PrintMessage(), this.self());
			this.terminate();
		}
	}

	protected void handle(RegistrationMessage message) {
		this.context().watch(this.sender());
		this.workers.add(this.sender());
		this.uninitializedWorkers.add(this.sender());
		this.log().info("Registered {}", this.sender());

		if (this.readingDone) {
			this.self().tell(new InitializeWorkersMessage(), this.self());
		}
	}
	
	protected void handle(Terminated message) {
		this.context().unwatch(message.getActor());
		this.workers.remove(message.getActor());
		this.uninitializedWorkers.remove(message.getActor());
		this.idleWorkers.remove(message.getActor());

		Object lostWork = this.currentlyWorkingOn.remove(message.getActor());
		if(lostWork != null){
			this.openWorkPackets.add(lostWork);
		}

		this.log().info("Unregistered {}", message.getActor());
	}

	protected void tellWorkPacket(ActorRef actor, Object workPacket) {
	    // TODO: Is this necessary?
	    try {
            actor.tell((HintWorkPacketMessage)workPacket, this.self());
        } catch (ClassCastException e) {
            actor.tell((PasswordWorkPacketMessage)workPacket, this.self());
        }
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
