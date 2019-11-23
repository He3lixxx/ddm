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

	private Worker(ActorRef unsolvedHashProvider) throws NoSuchAlgorithmException {
		this.unsolvedHashProvider = unsolvedHashProvider;
		this.cluster = Cluster.get(this.context().system());

		// Create a LargeMessageForwarder for us. We don't need the reference as children will automatically be terminated
		// when we are sent the PoisonPill
		this.context().actorOf(LargeMessageForwarder.props(), LargeMessageForwarder.DEFAULT_NAME);
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

	private long highestRequestedIterationId = -1;

	private Set<ByteBuffer> unsolvedHashes;
	private boolean unsolvedHashesReceived = false;
	private long unsolvedHashesIterationId = -1;

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

				.match(Master.GetUnsolvedHashesMessage.class, this::handle)
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
		assert(this.unsolvedHashesReceived);

		Set<Character> reducedAlphabet = message.getAlphabet();
		Character[] characterList = new Character[reducedAlphabet.size()];
		reducedAlphabet.toArray(characterList);

		this.recursivelyCheckCombinationsForSolutions(
				characterList,
				message.getPrefixString(),
				message.getLength()
		);

		this.sender().tell(new Master.DoneMessage(message.getIterationId()), this.self());
	}

	private void handle(Master.HintWorkPacketMessage message){
		assert(this.unsolvedHashesReceived);

		// Might be a reference from the master, but it was crafted just for us, so this shouldn't be a problem.
		Set<Character> reducedAlphabet = message.getReducedAlphabet();

		Character[] characterList = new Character[reducedAlphabet.size()];
		reducedAlphabet.toArray(characterList);

		// In some really weird cases, this could lead to an inbox spam of the master inbox. I don't think we need to
		// handle that case, though (would only happen if we accidentally find all hashes really quickly)
		this.recursivelyCheckPermutationsForSolutions(
				characterList,
				characterList.length,
				message.getPrefixString()
		);

		this.sender().tell(new Master.DoneMessage(message.getIterationId()), this.self());
	}

	private void handle(Master.UnsolvedHashesMessage message){
		assert(!this.unsolvedHashesReceived);
		assert(message.getHashes() != null || message.getChunkOffset() != 0);

		if (message.getHashes() == null) {
			this.unsolvedHashesReceived = true;
			this.unsolvedHashesIterationId = message.getIterationId();

			this.sender().tell(new Master.UnsolvedHashesReceivedMessage(), this.self());
			this.self().tell(new Master.DistributeUnsolvedHashesMessage(), this.self());
			return;
		}

		if (message.getChunkOffset() == 0) {
			this.unsolvedHashes = new HashSet<>();
		}

		for (byte[] hintHash : message.getHashes()) {
			this.unsolvedHashes.add(wrap(hintHash));
		}

		this.sender().tell(new Master.SendUnsolvedHashesMessage(message.getChunkOffset() + 1, message.getIterationId()), this.self());
	}

	private void handle(Master.UnsolvedHashesReferenceMessage message){
		assert(!this.unsolvedHashesReceived);

		this.unsolvedHashesReceived = true;
		this.unsolvedHashesIterationId = message.getIterationId();
		this.unsolvedHashes = message.getHashes();

		// Message might have come from someone who is not the master, but we want to tell the master so we can get
		// work anyway
		this.master.tell(new Master.UnsolvedHashesReceivedMessage(), this.self());
	}

	private void handle(Master.SendUnsolvedHashesReferenceMessage message) {
		this.actorsWaitingForUnsolvedReferenceMessages.add(this.sender());
		this.highestRequestedIterationId = Math.max(message.getIterationId(), this.highestRequestedIterationId);

		this.self().tell(new Master.DistributeUnsolvedHashesMessage(), this.self());
	}

	private void handle(Master.DistributeUnsolvedHashesMessage message) {
		if (!this.unsolvedHashesReceived || this.highestRequestedIterationId > this.unsolvedHashesIterationId) {
			return;
		}

		assert(this.unsolvedHashes != null);
		// We would like to somehow make the set immutable before sharing the instance, but didn't find a way that
		// guarantees no copies will be made, so we share a mutable set and trust us to not modify it at the receiver.
		Master.UnsolvedHashesReferenceMessage msg = new Master.UnsolvedHashesReferenceMessage(
				this.unsolvedHashes, this.unsolvedHashesIterationId
		);

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
			this.master = this.getContext().actorSelection(member.address() + "/user/" + Master.DEFAULT_NAME);
			this.master.tell(new Master.RegistrationMessage(), this.self());
			this.self().tell(new Master.GetUnsolvedHashesMessage(), this.self());
		}
	}

	private void handle(Master.GetUnsolvedHashesMessage message) {
		// The master might send us this multiple times if we need to iterate over huge input files.

		if (message.getIterationId() == this.unsolvedHashesIterationId) {
			return; // already up to date.
		}

		this.unsolvedHashes = null;
		this.unsolvedHashesReceived = false;

		if (this.unsolvedHashProvider == null) {
			this.master.tell(new Master.SendUnsolvedHashesMessage(0, message.getIterationId()), this.self());
		} else {
			this.unsolvedHashProvider.tell(new Master.SendUnsolvedHashesReferenceMessage(message.getIterationId()), this.self());
		}
	}

	private void handle(MemberRemoved message) {
		if (this.masterSystem.equals(message.member()))
			this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
	}

	private byte[] hash(String line) {
		// The .getBytes call here is significantly slowing the system down. However, we are not guaranteed that
		// we will only get Single-Byte characters (which would allow us to just permute a byte array
		// benchmarking indicates this could be 20% faster).
		return this.digest.digest(line.getBytes(StandardCharsets.UTF_8));
	}

	// Check all permutations of an array using Heap's Algorithm
	// https://en.wikipedia.org/wiki/Heap's_algorithm
	// https://www.geeksforgeeks.org/heaps-algorithm-for-generating-permutations/
	private void recursivelyCheckPermutationsForSolutions(Character[] chars, int charsToPermute, String prefix) {
		if (charsToPermute == 1) {
			// You would think that re-using the same StringBuilder instance gives better performance - our profiling
			// said using one global StringBuilder had worse performance, though.
			StringBuilder sb = new StringBuilder(chars.length + prefix.length());
			sb.append(prefix);
			for (Character c : chars)
				sb.append(c.charValue());

			String raw_hint = sb.toString();
			byte[] hashBytes = hash(raw_hint);
			ByteBuffer wrappedHash = wrap(hashBytes);
			if (this.unsolvedHashes.contains(wrappedHash))
				this.sender().tell(new Master.HintSolvedMessage(hashBytes, raw_hint), this.self());
		}

		for (int i = 0; i < charsToPermute; i++) {
			this.recursivelyCheckPermutationsForSolutions(chars, charsToPermute - 1, prefix);

			if (charsToPermute % 2 == 1) {
				// If size is odd, swap first and last element
				char temp = chars[0];
				chars[0] = chars[charsToPermute - 1];
				chars[charsToPermute - 1] = temp;
			} else {
				// If size is even, swap i-th and last element
				char temp = chars[i];
				chars[i] = chars[charsToPermute - 1];
				chars[charsToPermute - 1] = temp;
			}
		}
	}

	// Check all combinations of length chars_left_to_add of a character set.
	// https://www.geeksforgeeks.org/print-all-combinations-of-given-length/
	private void recursivelyCheckCombinationsForSolutions(Character[] base_chars, String prefix, int passwordLength) {
		if (prefix.length() == passwordLength)
		{
			byte[] hashBytes = hash(prefix);
			ByteBuffer wrappedHash = wrap(hashBytes);
			if (this.unsolvedHashes.contains(wrappedHash))
				this.sender().tell(new Master.PasswordSolvedMessage(hashBytes, prefix), this.self());

			return;
		}

		for (Character base_char : base_chars)
		{
			// You would think that using a StringBuilder with a push here and a pop after the recursive call would yield
			// better performance. Our benchmarking said this is faster, though.
			String recursionPrefix = prefix + base_char;
			recursivelyCheckCombinationsForSolutions(base_chars, recursionPrefix, passwordLength);
		}
	}
}