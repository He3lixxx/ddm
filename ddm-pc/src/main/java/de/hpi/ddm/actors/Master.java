package de.hpi.ddm.actors;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.actor.Terminated;
import de.hpi.ddm.structures.HexStringParser;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class Master extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////
	
	public static final String DEFAULT_NAME = "master";

	public static Props props(final ActorRef reader, final ActorRef collector) {
		return Props.create(Master.class, () -> new Master(reader, collector));
	}

	public Master(final ActorRef reader, final ActorRef collector) {
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
	public static class BatchMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private List<String[]> lines;
	}

	@Data
	public static class RegistrationMessage implements Serializable {
		private static final long serialVersionUID = 3303081601659723997L;
	}

	@Data
	public static class CreateHintWorkPacketsMessage implements Serializable {
		private static final long serialVersionUID = 4016375330343989553L;
	}

	@Data
	public static class InitializeWorkersMessage implements Serializable {
		private static final long serialVersionUID = 5705955020161158225L;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class UnsolvedHashesMessage implements Serializable {
		private static final long serialVersionUID = 8266910043406252422L;
		private Set<byte[]> hintHashes;
		private Set<byte[]> passwordHashes;
	}

	@Data
	public static class UnsolvedHashesReceivedMessage implements Serializable {
		private static final long serialVersionUID = 8266910043406252422L;
	}


	@Data
	public static class DistributeHintWorkPacketsMessage implements Serializable {
		private static final long serialVersionUID = 3327522514637238884L;
	}

	// Structures to efficiently distribute work among workers
	@Data @NoArgsConstructor @AllArgsConstructor
	private static class HintWorkPacketMessage implements Serializable {
		private static final long serialVersionUID = 1147004165303224462L;
		private Set<Character> alphabet;
		private char missingChar;
		// TODO Später: char startChar; // für die Permutation
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	private static class HintSolvedMessage implements Serializable {
		private static final long serialVersionUID = 3443862827428452603L;
		private byte[] hash;
		private String hint;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	private static class PasswordSolvedMessage implements Serializable {
		private static final long serialVersionUID = 5219945881030570315L;
		private byte[] hash;
		private String password;
	}

	@Data
	private static class DoneMessage implements Serializable {
		private static final long serialVersionUID = 2476247634500726940L;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	private static class PasswordWorkPacketMessage implements Serializable {
		private static final long serialVersionUID = 4661499214826867244L;
		private Set<Character> reducedAlphabet;
		private int length;
		// TODO später: char startChar;
	}

	
	/////////////////
	// Actor State //
	/////////////////


	// Structures to internally keep track of solved and unsolved tasks

	@Data @NoArgsConstructor @AllArgsConstructor
	private static class CsvEntry {
		private int id;
		private String name;
		private byte[] passwordHash;  // TODO: Brauchen wir diese hashes?
		private byte[][] hintHashes;

		// TODO Später: Eventuell weniger Speicher nutzen - solvedHints sollte nur zum Debuggen nötig sein.
		private String[] solvedHints;
		private Set<Character> reducedPasswordAlphabet;

		public void storeHintSolution(byte[] hintHash, String hint) {
			boolean found = false;
			for (int i = 0; i < hintHashes.length; ++i) {
				if (Arrays.equals(hintHashes[i], hintHash)) {
					solvedHints[i] = hint;

					Set<Character> hintSet = hint.chars().mapToObj(e->(char)e).collect(Collectors.toSet());
					reducedPasswordAlphabet.retainAll(hintSet);

					found = true;
				}
			}

			assert(found);
		}
	}

	// TODO Später: Eventuell byte[] für die Hashes durch BigInt ersetzen (Performance?)
	// TODO Später: We need to know whether we still have unsolved hint hashes

	// Will be filled when all csv lines have been received.
	private List<HintWorkPacketMessage> hintWorkPackets = new LinkedList<HintWorkPacketMessage>();

	// When a node goes down, we need to redistribute the work of the actors on this node
	private Map<ActorRef, HintWorkPacketMessage> currentlyWorkingOnHints = new HashMap<ActorRef, HintWorkPacketMessage>();

	// uninitialized means has not got information about the hashes we are searching yet
	private List<ActorRef> uninitializedWorkers = new LinkedList<ActorRef>();
	// idle means that currently, no work packet is assigned to this worker
	private List<ActorRef> idleWorkers = new LinkedList<ActorRef>();

	// To be distributed to new actors before they can start working
	// TODO Später: Eventuell kann dieses Set nicht in einer Nachricht geschickt werden -> LMP oder so?
	private Set<byte[]> unsolvedHintHashes = new HashSet<byte[]>();  // Needed only in the first phase
	private Set<byte[]> unsolvedPasswordHashes = new HashSet<byte[]>();  // Needed only in the second phase

	// TODO Später: Dynamische Verteilung bei gelösten hashes, damit alle anderen Knoten diesen hash nicht mehr prüfen

	private ArrayList<CsvEntry> csvEntries = new ArrayList<CsvEntry>();

	// For fast lookup when a worker has found the raw string for a hash, we keep this lookup table
	private Map<byte[], List<CsvEntry> > hashToEntry = new HashMap<byte[], List<CsvEntry>>();

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

	protected void addHashEntryPairToEntryLookupMap(byte[] hash, CsvEntry entry) {
		List<CsvEntry> hashToEntryMapEntry = this.hashToEntry.computeIfAbsent(entry.passwordHash, k -> new ArrayList<CsvEntry>());
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
				.match(Terminated.class, this::handle)
				.match(RegistrationMessage.class, this::handle)
				.match(CreateHintWorkPacketsMessage.class, this::handle)
				.match(InitializeWorkersMessage.class, this::handle)
				.match(DoneMessage.class, this::handle)
				.match(DistributeHintWorkPacketsMessage.class, this::handle)
				.match(UnsolvedHashesReceivedMessage.class, this::handle)
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
			/* this.collector.tell(new Collector.PrintMessage(), this.self());
			this.terminate(); */
			return;
		}

		// tell reader to continue reading before we start computing so when we are done, the next message is ready
		this.reader.tell(new Reader.ReadMessage(), this.self());

		for (String[] line : message.getLines()) {
			CsvEntry entry = new CsvEntry();

			entry.id = Integer.parseInt(line[0]);
			entry.name = line[1];
			entry.passwordHash = HexStringParser.parse(line[4]);
			entry.hintHashes = new byte[line.length - 5][];
			entry.reducedPasswordAlphabet = new HashSet<>(this.passwordChars);
			for (int i = 5; i < line.length; ++i) {
				entry.hintHashes[i - 5] = HexStringParser.parse(line[i]);
			}

			int passwordLength = Integer.parseInt(line[3]);
			if (this.passwordLength == -1) {
				this.passwordChars = line[2].chars().mapToObj(e->(char)e).collect(Collectors.toSet());
				this.passwordLength = passwordLength;
			} else {
				assert(passwordLength == this.passwordLength);
				// TODO: This is duplicated across the code. Refactor.
				assert(line[2].chars().mapToObj(e->(char)e).collect(Collectors.toSet()).equals(this.passwordChars));
			}

			this.csvEntries.add(entry);

			this.addHashEntryPairToEntryLookupMap(entry.passwordHash, entry);
			this.unsolvedPasswordHashes.add(entry.passwordHash);

			for (int i = 0; i < entry.hintHashes.length; ++i) {
				this.addHashEntryPairToEntryLookupMap(entry.hintHashes[i], entry);
				this.unsolvedHintHashes.add(entry.hintHashes[i]);
			}
		}
	}

	protected void handle(CreateHintWorkPacketsMessage message) {
		// TODO: Improve: Distribute using a fixed first character for each packet.
		for (char c : this.passwordChars) {
			this.hintWorkPackets.add(new HintWorkPacketMessage(this.passwordChars, c));
		}

		this.self().tell(new DistributeHintWorkPacketsMessage(), this.self());
	}

	protected void handle(DistributeHintWorkPacketsMessage message) {
		Iterator<HintWorkPacketMessage> hintWorkPacketIterator = this.hintWorkPackets.iterator();
		Iterator<ActorRef> actorIterator = this.idleWorkers.iterator();

		while (hintWorkPacketIterator.hasNext() && actorIterator.hasNext()) {
			HintWorkPacketMessage workPacket = hintWorkPacketIterator.next();
			hintWorkPacketIterator.remove();

			ActorRef actor = actorIterator.next();
			actorIterator.remove();

			actor.tell(workPacket, this.self());
			this.currentlyWorkingOnHints.put(actor, workPacket);
		}
	}

	protected void handle(InitializeWorkersMessage message) {
		// TODO: Böse: die Member sind nicht konstant - set differenz hier bestimmen und eine Kopie erstellen?
		UnsolvedHashesMessage msg = new UnsolvedHashesMessage(this.unsolvedHintHashes, this.unsolvedPasswordHashes);

		for (ActorRef worker : this.uninitializedWorkers) {
			// TODO: What happens if the hashes are too big for one message here?)
			worker.tell(msg, this.self());
		}
	}

	protected void handle(UnsolvedHashesReceivedMessage message) {
		this.uninitializedWorkers.remove(this.sender());
		this.idleWorkers.add(this.sender());

		this.self().tell(new DistributeHintWorkPacketsMessage(), this.self());
	}

	protected void handle(DoneMessage message) {
		this.currentlyWorkingOnHints.remove(this.sender());
		this.idleWorkers.add(this.sender());
		this.self().tell(new DistributeHintWorkPacketsMessage(), this.self());
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
		//TODO: wahrscheinlich viel code duplication durch handling von hints and passwords separat
		this.context().unwatch(message.getActor());
		this.workers.remove(message.getActor());
		this.uninitializedWorkers.remove(message.getActor());
		this.idleWorkers.remove(message.getActor());

		//TODO: performance besser durch iterator use
		HintWorkPacketMessage lostWork = this.currentlyWorkingOnHints.get(message.getActor());
		if(lostWork != null){
			this.currentlyWorkingOnHints.remove(message.getActor());
			this.hintWorkPackets.add(lostWork);
		}

		this.log().info("Unregistered {}", message.getActor());
	}
}
