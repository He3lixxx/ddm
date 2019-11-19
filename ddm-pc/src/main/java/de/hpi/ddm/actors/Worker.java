package de.hpi.ddm.actors;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.cluster.Cluster;
import akka.cluster.ClusterEvent.CurrentClusterState;
import akka.cluster.ClusterEvent.MemberRemoved;
import akka.cluster.ClusterEvent.MemberUp;
import akka.cluster.Member;
import akka.cluster.MemberStatus;
import de.hpi.ddm.MasterSystem;

import static java.nio.ByteBuffer.wrap;

public class Worker extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "worker";

	public static Props props() {
		return Props.create(Worker.class);
	}

	public Worker() throws NoSuchAlgorithmException {
		this.cluster = Cluster.get(this.context().system());
	}

	////////////////////
	// Actor Messages //
	////////////////////

	/////////////////
	// Actor State //
	/////////////////

	private Member masterSystem;
	private final Cluster cluster;

	private Set<ByteBuffer> unsolvedHintHashes;
	private Set<ByteBuffer> unsolvedPasswordHashes;

	private MessageDigest digest = MessageDigest.getInstance("SHA-256");

	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	@Override
	public void preStart() {
		Reaper.watchWithDefaultReaper(this);

		this.cluster.subscribe(this.self(), MemberUp.class, MemberRemoved.class);
	}

	@Override
	public void postStop() {
		this.cluster.unsubscribe(this.self());
	}

	////////////////////
	// Actor Behavior //
	////////////////////

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(CurrentClusterState.class, this::handle)
				.match(MemberUp.class, this::handle)
				.match(MemberRemoved.class, this::handle)
				.match(Master.UnsolvedHashesMessage.class, this::handle)
				.match(Master.HintWorkPacketMessage.class, this::handle)
				.match(Master.PasswordWorkPacketMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handle(Master.PasswordWorkPacketMessage message){
		//TODO
		//Schleife die alle Kombinationen des Grundalphabets probiert und hashed
		//if match in this.unsolvedPasswordHashes
		//this.sender().tell(new PasswordSolvedMessage)
	}

	private void handle(Master.HintWorkPacketMessage message){
		// We do not change the message as it might just be a passed reference if we're on the Master System.
		Set<Character> reducedAlphabet = new HashSet<Character>(message.getAlphabet());
		boolean returnValue = reducedAlphabet.remove(message.getMissingChar());
		assert(returnValue);

		Character[] characterList = new Character[reducedAlphabet.size()];
		reducedAlphabet.toArray(characterList);

		// In some really weird cases, this could lead to an inbox spam of the master inbox. I don't think we need to
		// handle that case, though (would only happen if we accidentally find all hashes really quickly)
		this.recursivelyCheckPermutationsForSolutions(characterList, characterList.length, characterList.length);

		this.sender().tell(new Master.DoneMessage(), this.self());
	}

	//receive the sets of unsolved hashes and save them locally
	//TODO: possible improvement - save them only once per node instead of once per actor -- use Akka Distributed Data
	private void handle(Master.UnsolvedHashesMessage message){
		this.unsolvedHintHashes = message.getHintHashes();
		this.unsolvedPasswordHashes = message.getPasswordHashes();

		this.sender().tell(new Master.UnsolvedHashesReceivedMessage(), this.self());
	}

	private void handle(CurrentClusterState message) {
		message.getMembers().forEach(member -> {
			if (member.status().equals(MemberStatus.up()))
				this.register(member);
		});
	}

	private void handle(MemberUp message) {
		this.register(message.member());
	}

	private void register(Member member) {
		if ((this.masterSystem == null) && member.hasRole(MasterSystem.MASTER_ROLE)) {
			this.masterSystem = member;

			this.getContext()
					.actorSelection(member.address() + "/user/" + Master.DEFAULT_NAME)
					.tell(new Master.RegistrationMessage(), this.self());
		}
	}

	private void handle(MemberRemoved message) {
		if (this.masterSystem.equals(message.member()))
			this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
	}

	private byte[] hash(String line) {
		return this.digest.digest(String.valueOf(line).getBytes(StandardCharsets.UTF_8));
	}

	public static String hashToString(ByteBuffer hash) {
		StringBuilder stringBuilder = new StringBuilder();

		ByteBuffer copy = hash.duplicate(); // will only duplicate the internally stored position.
		while(copy.hasRemaining()) {
			stringBuilder.append(Integer.toString((copy.get() & 0xff) + 0x100, 16).substring(1));
		}
		return stringBuilder.toString();
	}

	// Generating all permutations of an array using Heap's Algorithm
	// https://en.wikipedia.org/wiki/Heap's_algorithm
	// https://www.geeksforgeeks.org/heaps-algorithm-for-generating-permutations/
	private void recursivelyCheckPermutationsForSolutions(Character[] chars, int charsSize, int permutationSize) {
		if (charsSize == 1)
			this.checkPermutationForSolution(chars, this.unsolvedHintHashes);

		for (int i = 0; i < charsSize; i++) {
			this.recursivelyCheckPermutationsForSolutions(chars, charsSize - 1, permutationSize);

			if (charsSize % 2 == 1) {
				// If size is odd, swap first and last element
				char temp = chars[0];
				chars[0] = chars[charsSize - 1];
				chars[charsSize - 1] = temp;
			} else {
				// If size is even, swap i-th and last element
				char temp = chars[i];
				chars[i] = chars[charsSize - 1];
				chars[charsSize - 1] = temp;
			}
		}
	}

	private void checkPermutationForSolution(Character[] chars, Set<ByteBuffer> searchedHashes) {
		StringBuilder sb = new StringBuilder(chars.length);
		for (Character c : chars)
			sb.append(c.charValue());

		String raw = sb.toString();

		ByteBuffer hash = wrap(hash(raw));
		if (searchedHashes.contains(hash)) {
			this.sender().tell(new Master.HintSolvedMessage(hash, raw), this.self());
		}
	}
}