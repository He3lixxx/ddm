package de.hpi.ddm.actors;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

import akka.actor.*;
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

	public static Props props(ActorRef unsolvedHashProvider) {
		return Props.create(Worker.class, () -> new Worker(unsolvedHashProvider));
}

	public Worker(ActorRef unsolvedHashProvider) throws NoSuchAlgorithmException {
		this.unsolvedHashProvider = unsolvedHashProvider;
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

	// This is a actor on the same system that can provide us with the unsolved hashes (by passing a reference inside
	// the system). It can also be null. In this case, _this_ actor is the provider of this system and needs to collect
	// the unsolved hashes from the masterSystem.
	private ActorRef unsolvedHashProvider;
	private ActorSelection master;

	private Set<ActorRef> actorsWaitingForUnsolvedReferenceMessages = new HashSet<>();

	private Set<ByteBuffer> unsolvedHashes;
	private boolean unsolvedHashesReceived = false;

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
				.match(Master.UnsolvedHashesReferenceMessage.class, this::handle)

				.match(Master.SendUnsolvedHashesReferenceMessage.class, this::handle)
				.match(Master.DistributeUnsolvedHashesMessage.class, this::handle)

				.match(Master.HintWorkPacketMessage.class, this::handle)
				.match(Master.PasswordWorkPacketMessage.class, this::handle)

				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handle(Master.PasswordWorkPacketMessage message){
		Set<Character> reducedAlphabet = message.getAlphabet();

		Character[] characterList = new Character[reducedAlphabet.size()];
		reducedAlphabet.toArray(characterList);

		this.recursivelyCheckCombinationsForSolutions(
				characterList,
				Character.toString(message.getPrefixChar()),
				message.getLength() - 1
		);

		this.sender().tell(new Master.DoneMessage(), this.self());
	}

	private void handle(Master.HintWorkPacketMessage message){
		// We do not change the message as it might just be a passed reference if we're on the Master System.
		Set<Character> reducedAlphabet = new HashSet<Character>(message.getReducedAlphabet());

		// We remove the char from the alphabet on the worker because we don't want to create too many sets on the master
		boolean returnValue = reducedAlphabet.remove(message.getPrefixChar());
		assert(returnValue);

		Character[] characterList = new Character[reducedAlphabet.size()];
		reducedAlphabet.toArray(characterList);

		// In some really weird cases, this could lead to an inbox spam of the master inbox. I don't think we need to
		// handle that case, though (would only happen if we accidentally find all hashes really quickly)
		this.recursivelyCheckPermutationsForSolutions(
				characterList,
				characterList.length,
				message.getPrefixChar()
		);

		this.sender().tell(new Master.DoneMessage(), this.self());
	}

	private void handle(Master.UnsolvedHashesMessage message){
		if (message.getHashes() == null) {
			this.unsolvedHashesReceived = true;
			this.sender().tell(new Master.UnsolvedHashesReceivedMessage(), this.self());
			this.self().tell(new Master.DistributeUnsolvedHashesMessage(), this.self());
			return;
		}

		if (message.getChunkOffset() == 0) {
			this.unsolvedHashes = new HashSet<>();
		}

		this.log().info("Unsolved hashes received as serialized data -- offset " + message.getChunkOffset());
		for (byte[] hintHash : message.getHashes()) {
			this.unsolvedHashes.add(wrap(hintHash));
		}

		this.sender().tell(new Master.SendUnsolvedHashesMessage(message.getChunkOffset() + 1), this.self());
	}

	private void handle(Master.UnsolvedHashesReferenceMessage message){
		this.log().info("Unsolved hashes received as reference");
		this.unsolvedHashes = message.getHashes();

		// Message might have come from someone who is _not_ the master, but we want to tell the master so we can get
		// work anyway
		this.master.tell(new Master.UnsolvedHashesReceivedMessage(), this.self());
	}

	private void handle(Master.SendUnsolvedHashesReferenceMessage message) {
		this.actorsWaitingForUnsolvedReferenceMessages.add(this.sender());
		this.self().tell(new Master.DistributeUnsolvedHashesMessage(), this.self());
	}

	private void handle(Master.DistributeUnsolvedHashesMessage message) {
		if (!this.unsolvedHashesReceived)
			return;

		// TODO: Before sharing, make read only to ensure multithreading correctness?
		Master.UnsolvedHashesReferenceMessage msg = new Master.UnsolvedHashesReferenceMessage(this.unsolvedHashes);

		for (ActorRef actor : this.actorsWaitingForUnsolvedReferenceMessages) {
			actor.tell(msg, this.self());
		}
		this.actorsWaitingForUnsolvedReferenceMessages.clear();
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
			ActorSelection masterActor = this.getContext().actorSelection(member.address() + "/user/" + Master.DEFAULT_NAME);

			this.master = masterActor;
			this.master.tell(new Master.RegistrationMessage(), this.self());
			if (this.unsolvedHashProvider == null) {
				masterActor.tell(new Master.SendUnsolvedHashesMessage(0), this.self());
			} else {
				this.unsolvedHashProvider.tell(new Master.SendUnsolvedHashesReferenceMessage(), this.self());
			}
		}
	}

	private void handle(MemberRemoved message) {
		if (this.masterSystem.equals(message.member()))
			this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
	}

	private byte[] hash(String line) {
		return this.digest.digest(line.getBytes(StandardCharsets.UTF_8));
	}

	// Check all permutations of an array using Heap's Algorithm
	// https://en.wikipedia.org/wiki/Heap's_algorithm
	// https://www.geeksforgeeks.org/heaps-algorithm-for-generating-permutations/
	private void recursivelyCheckPermutationsForSolutions(Character[] chars, int charsSize, char prefix) {
		if (charsSize == 1) {
			StringBuilder sb = new StringBuilder(chars.length + 1);
			sb.append(prefix);
			for (Character c : chars)
				sb.append(c.charValue());

			String raw_hint = sb.toString();
			byte[] hashBytes = hash(raw_hint);
			ByteBuffer wrappedHash = wrap(hashBytes);
			if (this.unsolvedHashes.contains(wrappedHash))
				this.sender().tell(new Master.HintSolvedMessage(hashBytes, raw_hint), this.self());
		}

		for (int i = 0; i < charsSize; i++) {
			this.recursivelyCheckPermutationsForSolutions(chars, charsSize - 1, prefix);

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

	// Check all combinations of length chars_left_to_add of a character set.
	// https://www.geeksforgeeks.org/print-all-combinations-of-given-length/
	private void recursivelyCheckCombinationsForSolutions(Character[] base_chars, String prefix, int chars_left_to_add) {
		if (chars_left_to_add == 0)
		{
			byte[] hashBytes = hash(prefix);
			ByteBuffer wrappedHash = wrap(hashBytes);
			if (this.unsolvedHashes.contains(wrappedHash))
				this.sender().tell(new Master.PasswordSolvedMessage(hashBytes, prefix), this.self());

			return;
		}

		for (Character base_char : base_chars)
		{
			String recursionPrefix = prefix + base_char;
			recursivelyCheckCombinationsForSolutions(base_chars, recursionPrefix, chars_left_to_add - 1);
		}
	}
}